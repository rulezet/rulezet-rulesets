rule sig_20161206_80b348bbcf7afe2d9eb543d4cd2d0ca1 {
  meta:
    description = "datamaliciousorder - file 20161206_80b348bbcf7afe2d9eb543d4cd2d0ca1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb410cb3e1d88334e138a3565fef87faf49c06316054461f224ff863f358f99f"

  strings:
    $s1 = "function _Bh1(s) {var _KMo7 = new Date();_KMo7.setUTCFullYear(\"2003\");if (_KMo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bh1(s) {var _KMo7 = new Date();_KMo7.setUTCFullYear(\"2003\");if (_KMo7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Zh1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}