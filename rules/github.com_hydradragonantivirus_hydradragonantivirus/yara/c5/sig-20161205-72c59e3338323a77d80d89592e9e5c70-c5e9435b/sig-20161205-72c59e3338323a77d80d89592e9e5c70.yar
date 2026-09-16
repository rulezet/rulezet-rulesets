rule sig_20161205_72c59e3338323a77d80d89592e9e5c70 {
  meta:
    description = "datamaliciousorder - file 20161205_72c59e3338323a77d80d89592e9e5c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba83ea24ff61079a8be65df1147089798f7a73b1ff981e35e7d8ec523aa1be4"

  strings:
    $s1 = "function _UNi9(s) {var _HJl7 = new Date();_HJl7.setUTCFullYear(\"2003\");if (_HJl7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UNi9(s) {var _HJl7 = new Date();_HJl7.setUTCFullYear(\"2003\");if (_HJl7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BVt9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}