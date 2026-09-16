rule sig_20161206_e26a7ec95cfad024636091f1f44415f1 {
  meta:
    description = "datamaliciousorder - file 20161206_e26a7ec95cfad024636091f1f44415f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2d4665343e4a834c58617f25219d83f45377dc1a624d848e1342de81d1c0b2c"

  strings:
    $s1 = "function _Sy3(s) {var _Vl2 = new Date();_Vl2.setUTCFullYear(\"2003\");if (_Vl2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sy3(s) {var _Vl2 = new Date();_Vl2.setUTCFullYear(\"2003\");if (_Vl2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _CHs2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}