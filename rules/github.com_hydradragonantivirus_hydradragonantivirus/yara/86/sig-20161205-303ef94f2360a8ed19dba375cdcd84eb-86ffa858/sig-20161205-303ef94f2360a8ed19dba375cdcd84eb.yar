rule sig_20161205_303ef94f2360a8ed19dba375cdcd84eb {
  meta:
    description = "datamaliciousorder - file 20161205_303ef94f2360a8ed19dba375cdcd84eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b12b604a07b79591898e24eb9f8a9ab5598874e5d0d5f9a79eebc29b8f2977"

  strings:
    $s1 = "function _RJt7(s) {var _KYg5 = new Date();_KYg5.setUTCFullYear(\"2003\");if (_KYg5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _RJt7(s) {var _KYg5 = new Date();_KYg5.setUTCFullYear(\"2003\");if (_KYg5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Jg2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}