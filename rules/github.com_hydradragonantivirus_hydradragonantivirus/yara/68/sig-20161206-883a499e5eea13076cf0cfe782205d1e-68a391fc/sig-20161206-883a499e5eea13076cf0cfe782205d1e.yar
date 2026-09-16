rule sig_20161206_883a499e5eea13076cf0cfe782205d1e {
  meta:
    description = "datamaliciousorder - file 20161206_883a499e5eea13076cf0cfe782205d1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b3f5963c52d574aaf1350d0f356634c8eea2596695cb34992d32ec3355231c9"

  strings:
    $s1 = "function _EZd0(s) {var _UPt8 = new Date();_UPt8.setUTCFullYear(\"2003\");if (_UPt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EZd0(s) {var _UPt8 = new Date();_UPt8.setUTCFullYear(\"2003\");if (_UPt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WJn8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}