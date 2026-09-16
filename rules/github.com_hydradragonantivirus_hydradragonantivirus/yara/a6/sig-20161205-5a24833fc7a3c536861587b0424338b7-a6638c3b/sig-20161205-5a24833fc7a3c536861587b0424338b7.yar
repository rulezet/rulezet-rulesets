rule sig_20161205_5a24833fc7a3c536861587b0424338b7 {
  meta:
    description = "datamaliciousorder - file 20161205_5a24833fc7a3c536861587b0424338b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db7039248d4590c0a8e43096eee69f8473336f62369c7d8c24be3694748b8294"

  strings:
    $s1 = "function _ZEm0(s) {var _TAe1 = new Date();_TAe1.setUTCFullYear(\"2003\");if (_TAe1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZEm0(s) {var _TAe1 = new Date();_TAe1.setUTCFullYear(\"2003\");if (_TAe1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Lj1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}