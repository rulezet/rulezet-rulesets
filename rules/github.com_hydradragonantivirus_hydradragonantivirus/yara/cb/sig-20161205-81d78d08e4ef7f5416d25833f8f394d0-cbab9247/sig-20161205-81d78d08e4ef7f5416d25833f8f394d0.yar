rule sig_20161205_81d78d08e4ef7f5416d25833f8f394d0 {
  meta:
    description = "datamaliciousorder - file 20161205_81d78d08e4ef7f5416d25833f8f394d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "765748dc0f5b0a5ca9e98302794c92a962528a66935f68b2836b877e96f6353e"

  strings:
    $s1 = "function _LIi9(s) {var _CTm3 = new Date();_CTm3.setUTCFullYear(\"2003\");if (_CTm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LIi9(s) {var _CTm3 = new Date();_CTm3.setUTCFullYear(\"2003\");if (_CTm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZPl3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}