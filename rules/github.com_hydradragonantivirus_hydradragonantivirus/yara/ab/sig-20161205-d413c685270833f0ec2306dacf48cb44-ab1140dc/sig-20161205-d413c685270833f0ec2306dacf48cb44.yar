rule sig_20161205_d413c685270833f0ec2306dacf48cb44 {
  meta:
    description = "datamaliciousorder - file 20161205_d413c685270833f0ec2306dacf48cb44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d89c2f73be1a31d83a9bc63fc29fff7e8e2f6cdf822ebfb1bca3df2f4da5418"

  strings:
    $s1 = "function _CAd8(s) {var _UZi4 = new Date();_UZi4.setUTCFullYear(\"2003\");if (_UZi4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CAd8(s) {var _UZi4 = new Date();_UZi4.setUTCFullYear(\"2003\");if (_UZi4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QHs5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}