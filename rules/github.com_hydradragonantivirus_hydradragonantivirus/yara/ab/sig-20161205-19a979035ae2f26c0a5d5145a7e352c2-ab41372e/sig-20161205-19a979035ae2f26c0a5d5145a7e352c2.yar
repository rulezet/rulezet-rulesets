rule sig_20161205_19a979035ae2f26c0a5d5145a7e352c2 {
  meta:
    description = "datamaliciousorder - file 20161205_19a979035ae2f26c0a5d5145a7e352c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a993db10f23ed9ab4cc3c95fb773a1dddad1610737375a991c1abcbfcabfca3b"

  strings:
    $s1 = "function _MTj9(s) {var _LJt6 = new Date();_LJt6.setUTCFullYear(\"2003\");if (_LJt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MTj9(s) {var _LJt6 = new Date();_LJt6.setUTCFullYear(\"2003\");if (_LJt6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UUy8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}