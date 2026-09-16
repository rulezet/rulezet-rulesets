rule sig_20161205_9966e608d3c07fcbe48e020783d5fbae {
  meta:
    description = "datamaliciousorder - file 20161205_9966e608d3c07fcbe48e020783d5fbae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78321258a1c33cca0cf20ebf1c68edfddb74b0b21bdc46269541f34c93c2c7a4"

  strings:
    $s1 = "function _Gz7(s) {var _Dr0 = new Date();_Dr0.setUTCFullYear(\"2003\");if (_Dr0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gz7(s) {var _Dr0 = new Date();_Dr0.setUTCFullYear(\"2003\");if (_Dr0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Md3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}