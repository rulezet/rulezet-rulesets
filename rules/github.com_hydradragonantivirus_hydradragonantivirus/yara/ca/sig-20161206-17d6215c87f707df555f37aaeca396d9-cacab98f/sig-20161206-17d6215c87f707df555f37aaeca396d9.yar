rule sig_20161206_17d6215c87f707df555f37aaeca396d9 {
  meta:
    description = "datamaliciousorder - file 20161206_17d6215c87f707df555f37aaeca396d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f441bc2f3f4def65514d62a99ce86112d9d7680bd3104b5a6e755e2b0b6922c"

  strings:
    $s1 = "function _Dv0(s) {var _Dz3 = new Date();_Dz3.setUTCFullYear(\"2003\");if (_Dz3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dv0(s) {var _Dz3 = new Date();_Dz3.setUTCFullYear(\"2003\");if (_Dz3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _DEg1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}