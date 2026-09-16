rule sig_20161206_a740f0cd2ddb1584f1051afcab09e941 {
  meta:
    description = "datamaliciousorder - file 20161206_a740f0cd2ddb1584f1051afcab09e941.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "196b81bec272027b53bc0d0692cd33bd11ec30c03e61836cf00b1ee8ab9b468e"

  strings:
    $s1 = "function _TLh5(s) {var _Ch7 = new Date();_Ch7.setUTCFullYear(\"2003\");if (_Ch7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TLh5(s) {var _Ch7 = new Date();_Ch7.setUTCFullYear(\"2003\");if (_Ch7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _DXz1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}