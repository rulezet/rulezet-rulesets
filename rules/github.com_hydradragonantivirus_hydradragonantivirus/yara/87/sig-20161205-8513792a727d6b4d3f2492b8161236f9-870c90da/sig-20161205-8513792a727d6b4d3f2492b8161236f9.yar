rule sig_20161205_8513792a727d6b4d3f2492b8161236f9 {
  meta:
    description = "datamaliciousorder - file 20161205_8513792a727d6b4d3f2492b8161236f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fea6650722acbdccf34d3f36b9bd8c7865c994934318245456f648b9108a899c"

  strings:
    $s1 = "function _Ho7(s) {var _EYq7 = new Date();_EYq7.setUTCFullYear(\"2003\");if (_EYq7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ho7(s) {var _EYq7 = new Date();_EYq7.setUTCFullYear(\"2003\");if (_EYq7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ys9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}