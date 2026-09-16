rule sig_20161206_80203703c7ccb8e9198f2ccdff8fcaf7 {
  meta:
    description = "datamaliciousorder - file 20161206_80203703c7ccb8e9198f2ccdff8fcaf7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b38dbb610883c4ff4f6efa7851c726ab5cd36c363c53951dabe82cead7c591b"

  strings:
    $s1 = "function _HJs9(s) {var _Yz2 = new Date();_Yz2.setUTCFullYear(\"2003\");if (_Yz2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HJs9(s) {var _Yz2 = new Date();_Yz2.setUTCFullYear(\"2003\");if (_Yz2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _KHv6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}