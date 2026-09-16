rule sig_20161205_ce31d3b3a23ba3728648a0de0e7cff09 {
  meta:
    description = "datamaliciousorder - file 20161205_ce31d3b3a23ba3728648a0de0e7cff09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b441e6b06518fcd06bf9ff8c2922121a999c37ff804b888d094017b1fb6342"

  strings:
    $s1 = "function _Cg0(s) {var _Nk6 = new Date();_Nk6.setUTCFullYear(\"2003\");if (_Nk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cg0(s) {var _Nk6 = new Date();_Nk6.setUTCFullYear(\"2003\");if (_Nk6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ep9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}