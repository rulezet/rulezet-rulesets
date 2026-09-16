rule sig_20161205_663d0903665d697f2a56bc1c07fa997f {
  meta:
    description = "datamaliciousorder - file 20161205_663d0903665d697f2a56bc1c07fa997f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8037f811028e3e9294428def23189b7bf460392a03cf659c712f9284345c9626"

  strings:
    $s1 = "function _Sn2(s) {var _Ro2 = new Date();_Ro2.setUTCFullYear(\"2003\");if (_Ro2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sn2(s) {var _Ro2 = new Date();_Ro2.setUTCFullYear(\"2003\");if (_Ro2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Nj9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}