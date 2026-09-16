rule sig_20161205_691f84903477d5dacd9d9814c034d5e1 {
  meta:
    description = "datamaliciousorder - file 20161205_691f84903477d5dacd9d9814c034d5e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5935436c9d85d3dc3c75d94b8ecf12d585986ff96c04d756f366fd57f309818c"

  strings:
    $s1 = "function _BKh8(s) {var _Td7 = new Date();_Td7.setUTCFullYear(\"2003\");if (_Td7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BKh8(s) {var _Td7 = new Date();_Td7.setUTCFullYear(\"2003\");if (_Td7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _CUv6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}