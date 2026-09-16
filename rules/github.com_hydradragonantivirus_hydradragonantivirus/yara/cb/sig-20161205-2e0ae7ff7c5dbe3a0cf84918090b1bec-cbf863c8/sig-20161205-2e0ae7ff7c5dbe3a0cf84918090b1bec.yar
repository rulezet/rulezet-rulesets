rule sig_20161205_2e0ae7ff7c5dbe3a0cf84918090b1bec {
  meta:
    description = "datamaliciousorder - file 20161205_2e0ae7ff7c5dbe3a0cf84918090b1bec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "115b5f5c96229f901186038224ef03021c2e2aaa3bf1d364b738a557905f5979"

  strings:
    $s1 = "function _MZp0(s) {var _ZOh6 = new Date();_ZOh6.setUTCFullYear(\"2003\");if (_ZOh6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MZp0(s) {var _ZOh6 = new Date();_ZOh6.setUTCFullYear(\"2003\");if (_ZOh6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _GFw3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}