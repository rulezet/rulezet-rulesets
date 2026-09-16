rule sig_20161205_abd225c94b5fc36fd6e27e99e2a4e958 {
  meta:
    description = "datamaliciousorder - file 20161205_abd225c94b5fc36fd6e27e99e2a4e958.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a33fa99065f1dd76eaeb149efdedb10794299fb3b28a460c0be9806c3740070a"

  strings:
    $s1 = "function _YQr4(s) {var _Qg1 = new Date();_Qg1.setUTCFullYear(\"2003\");if (_Qg1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YQr4(s) {var _Qg1 = new Date();_Qg1.setUTCFullYear(\"2003\");if (_Qg1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ACb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}