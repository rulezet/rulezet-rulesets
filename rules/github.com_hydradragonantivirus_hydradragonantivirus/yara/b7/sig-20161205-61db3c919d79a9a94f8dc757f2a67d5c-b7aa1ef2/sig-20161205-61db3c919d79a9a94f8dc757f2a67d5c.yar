rule sig_20161205_61db3c919d79a9a94f8dc757f2a67d5c {
  meta:
    description = "datamaliciousorder - file 20161205_61db3c919d79a9a94f8dc757f2a67d5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fe218ae6f9e12e6c98a2a39883a6aefa6da4820401d4d26fd879fada391cc9c"

  strings:
    $s1 = "function _KZs1(s) {var _KVa9 = new Date();_KVa9.setUTCFullYear(\"2003\");if (_KVa9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KZs1(s) {var _KVa9 = new Date();_KVa9.setUTCFullYear(\"2003\");if (_KVa9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VOk5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}