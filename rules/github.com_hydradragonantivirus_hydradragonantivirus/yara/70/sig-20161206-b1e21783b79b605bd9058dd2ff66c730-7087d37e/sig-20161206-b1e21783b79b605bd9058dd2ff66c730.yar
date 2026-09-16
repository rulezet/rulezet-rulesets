rule sig_20161206_b1e21783b79b605bd9058dd2ff66c730 {
  meta:
    description = "datamaliciousorder - file 20161206_b1e21783b79b605bd9058dd2ff66c730.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e9bb5a459ea3c4e59569e91fae1ce53d3ce675737ef13a1a79a830f783714ca"

  strings:
    $s1 = "function _Ym1(s) {var _Fq4 = new Date();_Fq4.setUTCFullYear(\"2003\");if (_Fq4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ym1(s) {var _Fq4 = new Date();_Fq4.setUTCFullYear(\"2003\");if (_Fq4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ca0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}