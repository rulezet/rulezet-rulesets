rule sig_20161205_46c793fdd2c415d0ac06ca39bbdad910 {
  meta:
    description = "datamaliciousorder - file 20161205_46c793fdd2c415d0ac06ca39bbdad910.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70fd123b71224cc8de844561ab57d4bc5030f3820c33454d39817a459f613f3d"

  strings:
    $s1 = "function _Xp7(s) {var _Zz7 = new Date();_Zz7.setUTCFullYear(\"2003\");if (_Zz7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xp7(s) {var _Zz7 = new Date();_Zz7.setUTCFullYear(\"2003\");if (_Zz7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TJf9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}