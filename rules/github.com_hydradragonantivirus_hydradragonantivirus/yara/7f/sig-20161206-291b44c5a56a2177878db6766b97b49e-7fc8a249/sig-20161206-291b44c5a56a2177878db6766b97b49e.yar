rule sig_20161206_291b44c5a56a2177878db6766b97b49e {
  meta:
    description = "datamaliciousorder - file 20161206_291b44c5a56a2177878db6766b97b49e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59df93f1a5d4ca73772d04b17b2641d1d8610e07bcdc299e12a1040e6e5f3623"

  strings:
    $s1 = "function _YTx8(s) {var _Th6 = new Date();_Th6.setUTCFullYear(\"2003\");if (_Th6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YTx8(s) {var _Th6 = new Date();_Th6.setUTCFullYear(\"2003\");if (_Th6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Js2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}