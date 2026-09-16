rule sig_20161205_87b9f821b1ef587ec9a82ab5eab46672 {
  meta:
    description = "datamaliciousorder - file 20161205_87b9f821b1ef587ec9a82ab5eab46672.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b5f0fad79fe54c5fbf4a054408c4c367d85f14ceb4488eca6da8c529bb247a5"

  strings:
    $s1 = "function _BXr8(s) {var _QEs8 = new Date();_QEs8.setUTCFullYear(\"2003\");if (_QEs8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BXr8(s) {var _QEs8 = new Date();_QEs8.setUTCFullYear(\"2003\");if (_QEs8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ce3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}