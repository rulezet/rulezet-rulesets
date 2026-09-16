rule sig_20161206_1599d6f8a653daaaafce912963389dd5 {
  meta:
    description = "datamaliciousorder - file 20161206_1599d6f8a653daaaafce912963389dd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fb6136816fa4e75774ec1d4647da192c6ab0f133edae44843a0d9972c552885"

  strings:
    $s1 = "function _UOr1(s) {var _Vl1 = new Date();_Vl1.setUTCFullYear(\"2003\");if (_Vl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UOr1(s) {var _Vl1 = new Date();_Vl1.setUTCFullYear(\"2003\");if (_Vl1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FTh5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}