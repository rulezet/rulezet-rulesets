rule sig_20161205_1b2f969de8d80089d8fd411e6d8e9885 {
  meta:
    description = "datamaliciousorder - file 20161205_1b2f969de8d80089d8fd411e6d8e9885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d86b27a3278bfff7df51b8f77e9e58f420a30f22d0abbc31ee756215e89d985c"

  strings:
    $s1 = "function _Yl4(s) {var _Ot2 = new Date();_Ot2.setUTCFullYear(\"2003\");if (_Ot2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yl4(s) {var _Ot2 = new Date();_Ot2.setUTCFullYear(\"2003\");if (_Ot2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Rx5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}