rule sig_20161205_e6043482e9a701d548c6d77b9f015525 {
  meta:
    description = "datamaliciousorder - file 20161205_e6043482e9a701d548c6d77b9f015525.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c8928646627ac3525328c1ddd79aaeb717d990ce9e7e463ba368492048910d"

  strings:
    $s1 = "function _AGt6(s) {var _HMg0 = new Date();_HMg0.setUTCFullYear(\"2003\");if (_HMg0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _AGt6(s) {var _HMg0 = new Date();_HMg0.setUTCFullYear(\"2003\");if (_HMg0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _CPc7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}