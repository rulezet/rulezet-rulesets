rule sig_20161205_558028c090a8636b1b926cfe41af5c20 {
  meta:
    description = "datamaliciousorder - file 20161205_558028c090a8636b1b926cfe41af5c20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34997de9cce5d121314ae06ac249a699bc637e3fb0e1c8509d2aa6588dd07f82"

  strings:
    $s1 = "function _MOp7(s) {var _Ug6 = new Date();_Ug6.setUTCFullYear(\"2003\");if (_Ug6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MOp7(s) {var _Ug6 = new Date();_Ug6.setUTCFullYear(\"2003\");if (_Ug6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _WAs7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}