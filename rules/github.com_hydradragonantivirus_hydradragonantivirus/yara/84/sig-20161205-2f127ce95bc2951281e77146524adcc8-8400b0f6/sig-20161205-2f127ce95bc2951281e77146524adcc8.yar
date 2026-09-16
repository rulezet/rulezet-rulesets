rule sig_20161205_2f127ce95bc2951281e77146524adcc8 {
  meta:
    description = "datamaliciousorder - file 20161205_2f127ce95bc2951281e77146524adcc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11ad918dad04e710e4322f10cb8de8068c64712eb4b1a9c192bc10afed90399c"

  strings:
    $s1 = "function _Hq5(s) {var _CEc8 = new Date();_CEc8.setUTCFullYear(\"2003\");if (_CEc8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hq5(s) {var _CEc8 = new Date();_CEc8.setUTCFullYear(\"2003\");if (_CEc8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _WCb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}