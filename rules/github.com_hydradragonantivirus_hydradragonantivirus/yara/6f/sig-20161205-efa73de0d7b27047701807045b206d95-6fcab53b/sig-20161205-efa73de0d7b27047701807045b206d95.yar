rule sig_20161205_efa73de0d7b27047701807045b206d95 {
  meta:
    description = "datamaliciousorder - file 20161205_efa73de0d7b27047701807045b206d95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c3825f1a743eea14884a6d70c00416ceee0bcdc54c29b9a6d349f2914e778df"

  strings:
    $s1 = "function _NIc5(s) {var _Td1 = new Date();_Td1.setUTCFullYear(\"2003\");if (_Td1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _NIc5(s) {var _Td1 = new Date();_Td1.setUTCFullYear(\"2003\");if (_Td1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Cw4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}