rule sig_20161205_318d40e39955320b3100f1b9c07e7f82 {
  meta:
    description = "datamaliciousorder - file 20161205_318d40e39955320b3100f1b9c07e7f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf5a8efbabd3b79ab001d14c042c42bf6965e8a325f0260f4df54b4a9bafa8aa"

  strings:
    $s1 = "function _Nn0(s) {var _Hx2 = new Date();_Hx2.setUTCFullYear(\"2003\");if (_Hx2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Nn0(s) {var _Hx2 = new Date();_Hx2.setUTCFullYear(\"2003\");if (_Hx2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QWo6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}