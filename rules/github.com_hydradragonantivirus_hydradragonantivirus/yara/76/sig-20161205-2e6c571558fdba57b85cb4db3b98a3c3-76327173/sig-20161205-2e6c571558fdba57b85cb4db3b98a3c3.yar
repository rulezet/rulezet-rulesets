rule sig_20161205_2e6c571558fdba57b85cb4db3b98a3c3 {
  meta:
    description = "datamaliciousorder - file 20161205_2e6c571558fdba57b85cb4db3b98a3c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8494b88e63351904e2e8cfb7f9f25ed4bd01a8e1b35cca65dff546dc5c01ccf"

  strings:
    $s1 = "function _Ki7(s) {var _AHi5 = new Date();_AHi5.setUTCFullYear(\"2003\");if (_AHi5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ki7(s) {var _AHi5 = new Date();_AHi5.setUTCFullYear(\"2003\");if (_AHi5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UXq4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}