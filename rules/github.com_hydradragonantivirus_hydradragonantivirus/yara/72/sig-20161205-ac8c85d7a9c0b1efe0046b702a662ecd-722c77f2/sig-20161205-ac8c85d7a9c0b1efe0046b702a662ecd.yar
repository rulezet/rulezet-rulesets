rule sig_20161205_ac8c85d7a9c0b1efe0046b702a662ecd {
  meta:
    description = "datamaliciousorder - file 20161205_ac8c85d7a9c0b1efe0046b702a662ecd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "953c66fbd2795954932e155f986e742bcc30f1854eabd1a978d2d34d0e209dbe"

  strings:
    $s1 = "function _Wo7(s) {var _Hl6 = new Date();_Hl6.setUTCFullYear(\"2003\");if (_Hl6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wo7(s) {var _Hl6 = new Date();_Hl6.setUTCFullYear(\"2003\");if (_Hl6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TMt6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}