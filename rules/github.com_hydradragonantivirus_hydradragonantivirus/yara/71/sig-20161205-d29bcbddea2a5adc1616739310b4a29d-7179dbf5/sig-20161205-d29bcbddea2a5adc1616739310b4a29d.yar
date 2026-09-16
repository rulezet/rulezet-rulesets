rule sig_20161205_d29bcbddea2a5adc1616739310b4a29d {
  meta:
    description = "datamaliciousorder - file 20161205_d29bcbddea2a5adc1616739310b4a29d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55d0a45d0cc46fc730495196eeb3746d3a1aea1cb15d22147c884649808f90fb"

  strings:
    $s1 = "function _Cw1(s) {var _Tr5 = new Date();_Tr5.setUTCFullYear(\"2003\");if (_Tr5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cw1(s) {var _Tr5 = new Date();_Tr5.setUTCFullYear(\"2003\");if (_Tr5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Lf2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}