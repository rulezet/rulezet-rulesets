rule sig_20161206_20feb776ca70953e7173cf7f440f0ad9 {
  meta:
    description = "datamaliciousorder - file 20161206_20feb776ca70953e7173cf7f440f0ad9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25ed7108f5b003ff649a03b8083ede7c31bee99e4975139eb27332b6a65273ec"

  strings:
    $s1 = "function _CZg2(s) {var _TFo8 = new Date();_TFo8.setUTCFullYear(\"2003\");if (_TFo8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CZg2(s) {var _TFo8 = new Date();_TFo8.setUTCFullYear(\"2003\");if (_TFo8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Jv5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}