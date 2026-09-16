rule sig_20161205_e7d3fc1620d2544873512332b05dc8f2 {
  meta:
    description = "datamaliciousorder - file 20161205_e7d3fc1620d2544873512332b05dc8f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39cebc9634cdd8ad8a18ce68d73f35a79f4fc1c1a8be4fa457f17232e6ae8056"

  strings:
    $s1 = "function _CGr4(s) {var _XAb6 = new Date();_XAb6.setUTCFullYear(\"2003\");if (_XAb6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CGr4(s) {var _XAb6 = new Date();_XAb6.setUTCFullYear(\"2003\");if (_XAb6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ve7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}