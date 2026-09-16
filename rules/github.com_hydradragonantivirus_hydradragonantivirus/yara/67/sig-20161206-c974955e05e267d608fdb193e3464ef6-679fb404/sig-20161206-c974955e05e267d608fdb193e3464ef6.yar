rule sig_20161206_c974955e05e267d608fdb193e3464ef6 {
  meta:
    description = "datamaliciousorder - file 20161206_c974955e05e267d608fdb193e3464ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8aedcea50ac5669164619e6ef59a53c694900c78570ed1a7815ab825350ce62"

  strings:
    $s1 = "function _WEx5(s) {var _Ai4 = new Date();_Ai4.setUTCFullYear(\"2003\");if (_Ai4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WEx5(s) {var _Ai4 = new Date();_Ai4.setUTCFullYear(\"2003\");if (_Ai4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Un1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}