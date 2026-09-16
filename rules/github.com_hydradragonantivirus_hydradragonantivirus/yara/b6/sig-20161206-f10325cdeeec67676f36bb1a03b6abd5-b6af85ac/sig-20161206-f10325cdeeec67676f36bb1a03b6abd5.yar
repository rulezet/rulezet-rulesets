rule sig_20161206_f10325cdeeec67676f36bb1a03b6abd5 {
  meta:
    description = "datamaliciousorder - file 20161206_f10325cdeeec67676f36bb1a03b6abd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b5994916027df3170a1eaaf66ff5b043cff4cbbcb77a90489784f63beab0e06"

  strings:
    $s1 = "function _ARx9(s) {var _Fr6 = new Date();_Fr6.setUTCFullYear(\"2003\");if (_Fr6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ARx9(s) {var _Fr6 = new Date();_Fr6.setUTCFullYear(\"2003\");if (_Fr6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Dc1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}