rule sig_20161205_ccc376e82a863c0f8061c31faf818187 {
  meta:
    description = "datamaliciousorder - file 20161205_ccc376e82a863c0f8061c31faf818187.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72f2a9b285f5f8a4de6478ad604b75825381cfed01620d568682acce8c49aa04"

  strings:
    $s1 = "function _JAi0(s) {var _Za6 = new Date();_Za6.setUTCFullYear(\"2003\");if (_Za6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JAi0(s) {var _Za6 = new Date();_Za6.setUTCFullYear(\"2003\");if (_Za6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _UXd3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}