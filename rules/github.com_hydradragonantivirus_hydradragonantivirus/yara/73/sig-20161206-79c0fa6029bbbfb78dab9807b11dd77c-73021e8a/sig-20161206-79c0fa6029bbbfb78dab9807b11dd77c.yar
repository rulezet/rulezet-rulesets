rule sig_20161206_79c0fa6029bbbfb78dab9807b11dd77c {
  meta:
    description = "datamaliciousorder - file 20161206_79c0fa6029bbbfb78dab9807b11dd77c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2eb52266f39b986ccb9ac35d32b6ce48e0091bb5ecbe7a2fe8c438134e8d655"

  strings:
    $s1 = "function _SYr4(s) {var _Rm9 = new Date();_Rm9.setUTCFullYear(\"2003\");if (_Rm9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SYr4(s) {var _Rm9 = new Date();_Rm9.setUTCFullYear(\"2003\");if (_Rm9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _KHk9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}