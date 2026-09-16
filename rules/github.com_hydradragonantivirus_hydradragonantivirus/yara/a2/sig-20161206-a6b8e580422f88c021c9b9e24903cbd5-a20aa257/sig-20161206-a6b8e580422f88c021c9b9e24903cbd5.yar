rule sig_20161206_a6b8e580422f88c021c9b9e24903cbd5 {
  meta:
    description = "datamaliciousorder - file 20161206_a6b8e580422f88c021c9b9e24903cbd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "212bc3a1a6df2c9b06fc0ccab40e6a2e08e04eae40cf5e07c5d23ad67cad6880"

  strings:
    $s1 = "function _BKv8(s) {var _Qq6 = new Date();_Qq6.setUTCFullYear(\"2003\");if (_Qq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BKv8(s) {var _Qq6 = new Date();_Qq6.setUTCFullYear(\"2003\");if (_Qq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _PRl7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}