rule sig_20161205_1f5c3ba114bbc8f6baf87650f97f2fa4 {
  meta:
    description = "datamaliciousorder - file 20161205_1f5c3ba114bbc8f6baf87650f97f2fa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "375dd727f8bb2f4f0638ffe27fc10dfb6d3dc12d9024b19ac185b6803258868d"

  strings:
    $s1 = "function _Gf9(s) {var _ILr2 = new Date();_ILr2.setUTCFullYear(\"2003\");if (_ILr2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gf9(s) {var _ILr2 = new Date();_ILr2.setUTCFullYear(\"2003\");if (_ILr2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Hj1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}