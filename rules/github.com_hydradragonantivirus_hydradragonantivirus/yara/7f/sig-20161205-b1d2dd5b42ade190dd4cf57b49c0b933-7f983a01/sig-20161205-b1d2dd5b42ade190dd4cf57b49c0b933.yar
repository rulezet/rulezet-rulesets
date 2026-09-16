rule sig_20161205_b1d2dd5b42ade190dd4cf57b49c0b933 {
  meta:
    description = "datamaliciousorder - file 20161205_b1d2dd5b42ade190dd4cf57b49c0b933.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7427cd72e8157af62d9ff430161d7cceafc5b23f7483e39c87814e00c003cd28"

  strings:
    $s1 = "function _Bo8(s) {var _DUv9 = new Date();_DUv9.setUTCFullYear(\"2003\");if (_DUv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bo8(s) {var _DUv9 = new Date();_DUv9.setUTCFullYear(\"2003\");if (_DUv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _WJt2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}