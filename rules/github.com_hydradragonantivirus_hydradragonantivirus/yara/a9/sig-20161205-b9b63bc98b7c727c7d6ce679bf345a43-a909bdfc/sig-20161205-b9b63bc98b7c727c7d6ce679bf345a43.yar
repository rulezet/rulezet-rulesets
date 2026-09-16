rule sig_20161205_b9b63bc98b7c727c7d6ce679bf345a43 {
  meta:
    description = "datamaliciousorder - file 20161205_b9b63bc98b7c727c7d6ce679bf345a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c139a1976ea03b091252f81117bc3a3b68465386bb8cf12df5a8d7fa144e771f"

  strings:
    $s1 = "function _Ug3(s) {var _Ox5 = new Date();_Ox5.setUTCFullYear(\"2003\");if (_Ox5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ug3(s) {var _Ox5 = new Date();_Ox5.setUTCFullYear(\"2003\");if (_Ox5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Jt4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}