rule sig_20161205_c66f343d8c589ee68c93fc7118663ae1 {
  meta:
    description = "datamaliciousorder - file 20161205_c66f343d8c589ee68c93fc7118663ae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca88da262b9f42d4bea67651493309e3db36bfa1c796e3c5fe03d1d69276c8b"

  strings:
    $s1 = "function _ZPi4(s) {var _Tf3 = new Date();_Tf3.setUTCFullYear(\"2003\");if (_Tf3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZPi4(s) {var _Tf3 = new Date();_Tf3.setUTCFullYear(\"2003\");if (_Tf3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _BBq9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}