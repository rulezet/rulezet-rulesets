rule sig_20161206_3b4af248a951526176c385150390b5f7 {
  meta:
    description = "datamaliciousorder - file 20161206_3b4af248a951526176c385150390b5f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1866d56a0b418bf01a15dc2afabe154bee236bac1d1612a4bc1b6631c474a2b6"

  strings:
    $s1 = "function _PWy9(s) {var _Jp8 = new Date();_Jp8.setUTCFullYear(\"2003\");if (_Jp8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PWy9(s) {var _Jp8 = new Date();_Jp8.setUTCFullYear(\"2003\");if (_Jp8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _OUw7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}