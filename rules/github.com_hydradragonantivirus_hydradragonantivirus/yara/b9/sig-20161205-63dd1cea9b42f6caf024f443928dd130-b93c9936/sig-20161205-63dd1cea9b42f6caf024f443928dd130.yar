rule sig_20161205_63dd1cea9b42f6caf024f443928dd130 {
  meta:
    description = "datamaliciousorder - file 20161205_63dd1cea9b42f6caf024f443928dd130.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d091a1b7524c79b5e34dfdd3253bc5164d202d01325aa2c41cb3be1fb5d2f397"

  strings:
    $s1 = "function _Dj4(s) {var _NLe8 = new Date();_NLe8.setUTCFullYear(\"2003\");if (_NLe8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dj4(s) {var _NLe8 = new Date();_NLe8.setUTCFullYear(\"2003\");if (_NLe8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Eg3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}