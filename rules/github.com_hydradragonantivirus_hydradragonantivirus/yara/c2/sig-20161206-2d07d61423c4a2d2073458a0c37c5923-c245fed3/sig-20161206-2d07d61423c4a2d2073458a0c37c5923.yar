rule sig_20161206_2d07d61423c4a2d2073458a0c37c5923 {
  meta:
    description = "datamaliciousorder - file 20161206_2d07d61423c4a2d2073458a0c37c5923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa5348764672d72fc66759d7958a1c5504d2f615c41da2bb46d8f5bf7674ad47"

  strings:
    $s1 = "function _Lo6(s) {var _Xy8 = new Date();_Xy8.setUTCFullYear(\"2003\");if (_Xy8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Lo6(s) {var _Xy8 = new Date();_Xy8.setUTCFullYear(\"2003\");if (_Xy8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Mx7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}