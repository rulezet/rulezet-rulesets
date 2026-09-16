rule sig_20161205_e1a0b14e97f77c94aba2f7a845457242 {
  meta:
    description = "datamaliciousorder - file 20161205_e1a0b14e97f77c94aba2f7a845457242.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbe3a08a54a878270110af29c50e463d1d00e0ba11aeb3cfd6cc43c4ba9f3e8d"

  strings:
    $s1 = "function _CCa1(s) {var _CPi2 = new Date();_CPi2.setUTCFullYear(\"2003\");if (_CPi2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CCa1(s) {var _CPi2 = new Date();_CPi2.setUTCFullYear(\"2003\");if (_CPi2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ISe9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}