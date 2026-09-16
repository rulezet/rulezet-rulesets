rule sig_20161205_7902a1c5f3b4f0ada9286c88da345029 {
  meta:
    description = "datamaliciousorder - file 20161205_7902a1c5f3b4f0ada9286c88da345029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e322741b6c4a22d0191a8fca064bc8ff9609bbdf918bedab7bb1836d598214d7"

  strings:
    $s1 = "function _CTg5(s) {var _LGk8 = new Date();_LGk8.setUTCFullYear(\"2003\");if (_LGk8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CTg5(s) {var _LGk8 = new Date();_LGk8.setUTCFullYear(\"2003\");if (_LGk8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Sg3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}