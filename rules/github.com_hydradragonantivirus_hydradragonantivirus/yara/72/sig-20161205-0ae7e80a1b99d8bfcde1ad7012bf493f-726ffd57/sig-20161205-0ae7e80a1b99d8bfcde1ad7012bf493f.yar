rule sig_20161205_0ae7e80a1b99d8bfcde1ad7012bf493f {
  meta:
    description = "datamaliciousorder - file 20161205_0ae7e80a1b99d8bfcde1ad7012bf493f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c8b35f6d5396932c8d96516774b76e884133ed988e354d2ba40c0599c6399a"

  strings:
    $s1 = "function _ENc7(s) {var _MPd7 = new Date();_MPd7.setUTCFullYear(\"2003\");if (_MPd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ENc7(s) {var _MPd7 = new Date();_MPd7.setUTCFullYear(\"2003\");if (_MPd7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UNe7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}