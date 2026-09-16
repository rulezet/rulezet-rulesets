rule sig_20161206_06a3c12087bbca50e9c68e00ab539264 {
  meta:
    description = "datamaliciousorder - file 20161206_06a3c12087bbca50e9c68e00ab539264.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83c24616160d78c9d0f959016c32ccc1fd4cf7bc633ea27d7512bb3a4b99ff97"

  strings:
    $s1 = "function _FGo1(s) {var _Ul6 = new Date();_Ul6.setUTCFullYear(\"2003\");if (_Ul6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FGo1(s) {var _Ul6 = new Date();_Ul6.setUTCFullYear(\"2003\");if (_Ul6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _YRz4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}