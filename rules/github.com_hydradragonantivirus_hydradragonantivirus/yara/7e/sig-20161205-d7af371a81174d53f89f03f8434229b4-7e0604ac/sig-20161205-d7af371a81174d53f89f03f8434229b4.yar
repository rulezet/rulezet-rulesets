rule sig_20161205_d7af371a81174d53f89f03f8434229b4 {
  meta:
    description = "datamaliciousorder - file 20161205_d7af371a81174d53f89f03f8434229b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e154a334eca6cb43f5701f6fc205b32809e5baa0002020bc5d3f447d8afa1a08"

  strings:
    $s1 = "function _Qs6(s) {var _Qf1 = new Date();_Qf1.setUTCFullYear(\"2003\");if (_Qf1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qs6(s) {var _Qf1 = new Date();_Qf1.setUTCFullYear(\"2003\");if (_Qf1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qh2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}