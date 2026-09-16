rule sig_20161205_59c427bf322d0c4f49b4ac141f4d4551 {
  meta:
    description = "datamaliciousorder - file 20161205_59c427bf322d0c4f49b4ac141f4d4551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "702aaf2cb2bb74818ea4cc55edf7886e47c2ebfa2cc554c05a32fdbb32bfb271"

  strings:
    $s1 = "function _IKc5(s) {var _XAk7 = new Date();_XAk7.setUTCFullYear(\"2003\");if (_XAk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IKc5(s) {var _XAk7 = new Date();_XAk7.setUTCFullYear(\"2003\");if (_XAk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VBb2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}