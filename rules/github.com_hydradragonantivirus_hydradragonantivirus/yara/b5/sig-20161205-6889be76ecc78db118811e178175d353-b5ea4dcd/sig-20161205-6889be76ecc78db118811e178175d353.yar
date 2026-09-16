rule sig_20161205_6889be76ecc78db118811e178175d353 {
  meta:
    description = "datamaliciousorder - file 20161205_6889be76ecc78db118811e178175d353.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c354991d80638357fd3144d31d9cd6fda56def2084d2743acf659351547e804f"

  strings:
    $s1 = "function _ZCk3(s) {var _Mq2 = new Date();_Mq2.setUTCFullYear(\"2003\");if (_Mq2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZCk3(s) {var _Mq2 = new Date();_Mq2.setUTCFullYear(\"2003\");if (_Mq2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GKm4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}