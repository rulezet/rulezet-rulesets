rule sig_20161205_8edfbabcd6ce5d763c1c483028ad504a {
  meta:
    description = "datamaliciousorder - file 20161205_8edfbabcd6ce5d763c1c483028ad504a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b13a561635a55b00c9580623f843e1a73f7629d17e748a070e12b3497df2196"

  strings:
    $s1 = "function _Oc4(s) {var _Sw1 = new Date();_Sw1.setUTCFullYear(\"2003\");if (_Sw1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Oc4(s) {var _Sw1 = new Date();_Sw1.setUTCFullYear(\"2003\");if (_Sw1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Jk5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}