rule sig_20161205_c1daa9f5386827660e54ac32374616d8 {
  meta:
    description = "datamaliciousorder - file 20161205_c1daa9f5386827660e54ac32374616d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "769669050553aeb97ea2ed72a6759926b92b8428e2fd25e7a9494cfd4bcc742f"

  strings:
    $s1 = "function _Qs5(s) {var _Ga3 = new Date();_Ga3.setUTCFullYear(\"2003\");if (_Ga3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qs5(s) {var _Ga3 = new Date();_Ga3.setUTCFullYear(\"2003\");if (_Ga3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _OLc3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}