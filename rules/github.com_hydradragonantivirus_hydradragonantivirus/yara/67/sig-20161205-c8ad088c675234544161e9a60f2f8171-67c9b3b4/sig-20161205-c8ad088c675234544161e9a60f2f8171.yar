rule sig_20161205_c8ad088c675234544161e9a60f2f8171 {
  meta:
    description = "datamaliciousorder - file 20161205_c8ad088c675234544161e9a60f2f8171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b61ca6cd1c4df2c9041adf78a898fdf7c2b8bab9c2bbfbdf9d3990d23563282b"

  strings:
    $s1 = "function _RFa5(s) {var _LNm1 = new Date();_LNm1.setUTCFullYear(\"2003\");if (_LNm1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _RFa5(s) {var _LNm1 = new Date();_LNm1.setUTCFullYear(\"2003\");if (_LNm1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Uj3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}