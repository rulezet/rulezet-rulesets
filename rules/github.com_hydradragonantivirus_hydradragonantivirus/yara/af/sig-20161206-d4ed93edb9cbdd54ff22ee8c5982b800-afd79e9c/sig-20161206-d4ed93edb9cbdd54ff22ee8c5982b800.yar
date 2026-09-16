rule sig_20161206_d4ed93edb9cbdd54ff22ee8c5982b800 {
  meta:
    description = "datamaliciousorder - file 20161206_d4ed93edb9cbdd54ff22ee8c5982b800.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bd23c8cd90331b4223db135a143545420488aafc4d176238d0441d4eb6ad949"

  strings:
    $s1 = "function _ELg4(s) {var _Zn7 = new Date();_Zn7.setUTCFullYear(\"2003\");if (_Zn7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ELg4(s) {var _Zn7 = new Date();_Zn7.setUTCFullYear(\"2003\");if (_Zn7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _IBu4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}