rule sig_20161206_c325c3b809201ac49d09ced8267f6e43 {
  meta:
    description = "datamaliciousorder - file 20161206_c325c3b809201ac49d09ced8267f6e43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50385cc3bb830a686bd049a3cc25ca3e27a7146cc928cd302c9bd0b23d0cc224"

  strings:
    $s1 = "function _QAa4(s) {var _Dz1 = new Date();_Dz1.setUTCFullYear(\"2003\");if (_Dz1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QAa4(s) {var _Dz1 = new Date();_Dz1.setUTCFullYear(\"2003\");if (_Dz1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Zh2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}