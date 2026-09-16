rule sig_20161206_5453381426c89e2ee4d95e58d53e1285 {
  meta:
    description = "datamaliciousorder - file 20161206_5453381426c89e2ee4d95e58d53e1285.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad82988bb7ce01df7f1d5f2aaf2440d42555f914f9782bb74198fb842fe07c24"

  strings:
    $s1 = "function _BEa6(s) {var _Rb0 = new Date();_Rb0.setUTCFullYear(\"2003\");if (_Rb0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BEa6(s) {var _Rb0 = new Date();_Rb0.setUTCFullYear(\"2003\");if (_Rb0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NKp9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}