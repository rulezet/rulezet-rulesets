rule sig_20161205_fc486e63f4b0e83cafbc18dee6edcaa9 {
  meta:
    description = "datamaliciousorder - file 20161205_fc486e63f4b0e83cafbc18dee6edcaa9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a0101c56bdbfafbca1b47c114e72ec69860e63827c44daa7856dfe30a8c739"

  strings:
    $s1 = "function _Fl7(s) {var _Eg6 = new Date();_Eg6.setUTCFullYear(\"2003\");if (_Eg6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fl7(s) {var _Eg6 = new Date();_Eg6.setUTCFullYear(\"2003\");if (_Eg6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _KBt6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}