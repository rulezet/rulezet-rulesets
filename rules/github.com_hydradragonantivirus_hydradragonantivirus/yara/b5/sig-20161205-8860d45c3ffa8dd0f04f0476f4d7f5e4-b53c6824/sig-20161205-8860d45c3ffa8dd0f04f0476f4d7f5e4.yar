rule sig_20161205_8860d45c3ffa8dd0f04f0476f4d7f5e4 {
  meta:
    description = "datamaliciousorder - file 20161205_8860d45c3ffa8dd0f04f0476f4d7f5e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdbebca9f3ed830789d7b95745b30dc02d167529841a5e9713966f416e75c851"

  strings:
    $s1 = "function _Ia8(s) {var _Jo8 = new Date();_Jo8.setUTCFullYear(\"2003\");if (_Jo8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ia8(s) {var _Jo8 = new Date();_Jo8.setUTCFullYear(\"2003\");if (_Jo8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _CNe8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}