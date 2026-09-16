rule sig_20161205_cc957a0dc89f55acecee73dbcb8ac94f {
  meta:
    description = "datamaliciousorder - file 20161205_cc957a0dc89f55acecee73dbcb8ac94f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a5d62a1cdcde65e7ecb35fc4467d235089278dc054d7cc3ac76affea0dcc567"

  strings:
    $s1 = "function _Um1(s) {var _OXt2 = new Date();_OXt2.setUTCFullYear(\"2003\");if (_OXt2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Um1(s) {var _OXt2 = new Date();_OXt2.setUTCFullYear(\"2003\");if (_OXt2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Df7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}