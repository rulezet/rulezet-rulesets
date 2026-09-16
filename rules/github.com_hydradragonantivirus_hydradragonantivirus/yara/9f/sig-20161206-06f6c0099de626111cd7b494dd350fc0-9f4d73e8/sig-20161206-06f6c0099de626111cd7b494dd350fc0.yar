rule sig_20161206_06f6c0099de626111cd7b494dd350fc0 {
  meta:
    description = "datamaliciousorder - file 20161206_06f6c0099de626111cd7b494dd350fc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e3f3b0aee16a51070bff7a685e5a1491850c576db9d3a710c1c7a39ab03846"

  strings:
    $s1 = "function _QEz0(s) {var _Vj9 = new Date();_Vj9.setUTCFullYear(\"2003\");if (_Vj9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QEz0(s) {var _Vj9 = new Date();_Vj9.setUTCFullYear(\"2003\");if (_Vj9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _MYw1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}