rule sig_20161205_b97af5f3abda885aeb65c5fbe5f70e13 {
  meta:
    description = "datamaliciousorder - file 20161205_b97af5f3abda885aeb65c5fbe5f70e13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16e823c3261406369dee5bf2a8725fc47a4f05a8e1ffaec54b6610db9bbfe6c0"

  strings:
    $s1 = "function _AQm8(s) {var _Qj9 = new Date();_Qj9.setUTCFullYear(\"2003\");if (_Qj9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AQm8(s) {var _Qj9 = new Date();_Qj9.setUTCFullYear(\"2003\");if (_Qj9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _STp5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}