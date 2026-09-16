rule sig_20161205_ff593099418f2bf52203972424c135f7 {
  meta:
    description = "datamaliciousorder - file 20161205_ff593099418f2bf52203972424c135f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78b913870ecaedeab73d1025c04388afcbf4b09e40f3c42f78ac5b95787cf765"

  strings:
    $s1 = "function _Qj3(s) {var _Ja1 = new Date();_Ja1.setUTCFullYear(\"2003\");if (_Ja1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qj3(s) {var _Ja1 = new Date();_Ja1.setUTCFullYear(\"2003\");if (_Ja1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ZNr0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}