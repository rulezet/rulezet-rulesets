rule sig_20161205_dabebbf76504d76f34bb0150a2af4d46 {
  meta:
    description = "datamaliciousorder - file 20161205_dabebbf76504d76f34bb0150a2af4d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "647575f3560c21dcf6b0863aefa173f12a71cfcb7fc21baa7466946c6cb76ddb"

  strings:
    $s1 = "function _Rq7(s) {var _Nb4 = new Date();_Nb4.setUTCFullYear(\"2003\");if (_Nb4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rq7(s) {var _Nb4 = new Date();_Nb4.setUTCFullYear(\"2003\");if (_Nb4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Nu5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}