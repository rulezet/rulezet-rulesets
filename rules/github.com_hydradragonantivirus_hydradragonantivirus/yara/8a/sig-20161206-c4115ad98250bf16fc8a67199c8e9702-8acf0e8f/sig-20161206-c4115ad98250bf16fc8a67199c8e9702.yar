rule sig_20161206_c4115ad98250bf16fc8a67199c8e9702 {
  meta:
    description = "datamaliciousorder - file 20161206_c4115ad98250bf16fc8a67199c8e9702.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d04f65775bee734da67ecfea7a1c841db0f099a1689661a4e6edebcd9006ea0"

  strings:
    $s1 = "function _BKq8(s) {var _LNz1 = new Date();_LNz1.setUTCFullYear(\"2003\");if (_LNz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BKq8(s) {var _LNz1 = new Date();_LNz1.setUTCFullYear(\"2003\");if (_LNz1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WVf4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}