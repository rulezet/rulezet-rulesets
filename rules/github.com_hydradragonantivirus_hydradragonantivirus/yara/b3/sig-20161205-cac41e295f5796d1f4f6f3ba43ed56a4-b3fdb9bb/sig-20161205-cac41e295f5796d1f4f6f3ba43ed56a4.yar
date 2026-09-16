rule sig_20161205_cac41e295f5796d1f4f6f3ba43ed56a4 {
  meta:
    description = "datamaliciousorder - file 20161205_cac41e295f5796d1f4f6f3ba43ed56a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb70c3af274b2288182975c7a43d2e38f9e5fa21ea23028a6c6a0379ffbd7db"

  strings:
    $s1 = "function _Ai6(s) {var _XNt6 = new Date();_XNt6.setUTCFullYear(\"2003\");if (_XNt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ai6(s) {var _XNt6 = new Date();_XNt6.setUTCFullYear(\"2003\");if (_XNt6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Gt9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}