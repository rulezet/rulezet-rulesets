rule sig_20161205_3e047bfd5b7af9863e5dc01f9a438369 {
  meta:
    description = "datamaliciousorder - file 20161205_3e047bfd5b7af9863e5dc01f9a438369.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f9a06fc0dbf421c8e59010dbe990ff844b702b21a0642bdc8ce583723df87ce"

  strings:
    $s1 = "function _Qh6(s) {var _Zf2 = new Date();_Zf2.setUTCFullYear(\"2003\");if (_Zf2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qh6(s) {var _Zf2 = new Date();_Zf2.setUTCFullYear(\"2003\");if (_Zf2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Mt2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}