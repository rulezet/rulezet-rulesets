rule sig_20161206_4e006d9b16486b55aa4d3b8e68396ac9 {
  meta:
    description = "datamaliciousorder - file 20161206_4e006d9b16486b55aa4d3b8e68396ac9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "003b5aca20006c286d03d79e8225eccc94a6662099ff599dae5ca1493f654748"

  strings:
    $s1 = "function _Zv4(s) {var _Ot2 = new Date();_Ot2.setUTCFullYear(\"2003\");if (_Ot2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zv4(s) {var _Ot2 = new Date();_Ot2.setUTCFullYear(\"2003\");if (_Ot2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _JRq8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}