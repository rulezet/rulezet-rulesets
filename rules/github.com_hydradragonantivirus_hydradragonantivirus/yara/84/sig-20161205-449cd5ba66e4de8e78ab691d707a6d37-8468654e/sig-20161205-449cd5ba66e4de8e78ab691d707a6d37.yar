rule sig_20161205_449cd5ba66e4de8e78ab691d707a6d37 {
  meta:
    description = "datamaliciousorder - file 20161205_449cd5ba66e4de8e78ab691d707a6d37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8034a911d82ba9ebbf10bfe4393d34140d26284715cb82ce2326fe5080f3686"

  strings:
    $s1 = "function _Pv8(s) {var _Mt6 = new Date();_Mt6.setUTCFullYear(\"2003\");if (_Mt6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pv8(s) {var _Mt6 = new Date();_Mt6.setUTCFullYear(\"2003\");if (_Mt6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _AEu8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}