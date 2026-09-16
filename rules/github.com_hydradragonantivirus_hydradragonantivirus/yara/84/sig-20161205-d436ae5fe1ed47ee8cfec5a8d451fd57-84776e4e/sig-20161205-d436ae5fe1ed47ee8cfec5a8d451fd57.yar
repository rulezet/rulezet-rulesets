rule sig_20161205_d436ae5fe1ed47ee8cfec5a8d451fd57 {
  meta:
    description = "datamaliciousorder - file 20161205_d436ae5fe1ed47ee8cfec5a8d451fd57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "199076e40ff4ca09f5db338d1001415afa6edc9474d5bbc08a6ce84a9eae2759"

  strings:
    $s1 = "function _Bs8(s) {var _Bd5 = new Date();_Bd5.setUTCFullYear(\"2003\");if (_Bd5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bs8(s) {var _Bd5 = new Date();_Bd5.setUTCFullYear(\"2003\");if (_Bd5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qv7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}