rule sig_20161205_76d04e170c614775ad8b16437e590c82 {
  meta:
    description = "datamaliciousorder - file 20161205_76d04e170c614775ad8b16437e590c82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0aaab8db95b66852d365cb64227976d2a51f59092b9ed4afacd095ff0d8e6fd"

  strings:
    $s1 = "function _Cn7(s) {var _Ja0 = new Date();_Ja0.setUTCFullYear(\"2003\");if (_Ja0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cn7(s) {var _Ja0 = new Date();_Ja0.setUTCFullYear(\"2003\");if (_Ja0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MUk8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}