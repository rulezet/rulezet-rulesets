rule sig_20161205_80b2395a72476b97b3fc382236d8bc1d {
  meta:
    description = "datamaliciousorder - file 20161205_80b2395a72476b97b3fc382236d8bc1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "171cfdb3b393a8948415f65a00f12096ee7f8578bb1f5300bfcd2e844ac5f1b7"

  strings:
    $s1 = "function _Ke6(s) {var _Cq8 = new Date();_Cq8.setUTCFullYear(\"2003\");if (_Cq8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ke6(s) {var _Cq8 = new Date();_Cq8.setUTCFullYear(\"2003\");if (_Cq8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XNr6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}