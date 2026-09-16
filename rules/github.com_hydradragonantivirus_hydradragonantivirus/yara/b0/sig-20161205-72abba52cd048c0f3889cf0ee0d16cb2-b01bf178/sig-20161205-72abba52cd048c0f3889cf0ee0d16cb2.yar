rule sig_20161205_72abba52cd048c0f3889cf0ee0d16cb2 {
  meta:
    description = "datamaliciousorder - file 20161205_72abba52cd048c0f3889cf0ee0d16cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "192c412e5322167d2ad5d9fbe9a1cd87d3aa8865e4b0a56683367e2b66a0b5d5"

  strings:
    $s1 = "function _Ej8(s) {var _Pn7 = new Date();_Pn7.setUTCFullYear(\"2003\");if (_Pn7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ej8(s) {var _Pn7 = new Date();_Pn7.setUTCFullYear(\"2003\");if (_Pn7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Md5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}