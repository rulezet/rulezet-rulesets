rule sig_20161205_f858d558d9d53af245e06ee7f61d0601 {
  meta:
    description = "datamaliciousorder - file 20161205_f858d558d9d53af245e06ee7f61d0601.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45674962886f25300d782555192f3450f07905c1343aad61121a865279e1e033"

  strings:
    $s1 = "function _BRe2(s) {var _Hz5 = new Date();_Hz5.setUTCFullYear(\"2003\");if (_Hz5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BRe2(s) {var _Hz5 = new Date();_Hz5.setUTCFullYear(\"2003\");if (_Hz5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ZAr9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}