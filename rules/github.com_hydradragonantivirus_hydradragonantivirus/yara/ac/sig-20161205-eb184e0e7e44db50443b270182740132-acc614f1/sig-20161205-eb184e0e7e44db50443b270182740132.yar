rule sig_20161205_eb184e0e7e44db50443b270182740132 {
  meta:
    description = "datamaliciousorder - file 20161205_eb184e0e7e44db50443b270182740132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8025fc9667c6f5e1d568e76603433898740f72b4fe62cffaf6dd7c5518ac0ef3"

  strings:
    $s1 = "function _PMd4(s) {var _Th4 = new Date();_Th4.setUTCFullYear(\"2003\");if (_Th4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PMd4(s) {var _Th4 = new Date();_Th4.setUTCFullYear(\"2003\");if (_Th4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RBm4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}