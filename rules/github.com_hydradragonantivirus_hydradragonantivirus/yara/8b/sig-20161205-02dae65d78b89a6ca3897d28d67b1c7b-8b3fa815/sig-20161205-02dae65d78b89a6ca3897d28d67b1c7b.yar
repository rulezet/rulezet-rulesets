rule sig_20161205_02dae65d78b89a6ca3897d28d67b1c7b {
  meta:
    description = "datamaliciousorder - file 20161205_02dae65d78b89a6ca3897d28d67b1c7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00816b204454337f3e013163897cbc458c26dc798f5929db345be0cc4ae3ec8e"

  strings:
    $s1 = "function _LRr2(s) {var _Yl2 = new Date();_Yl2.setUTCFullYear(\"2003\");if (_Yl2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LRr2(s) {var _Yl2 = new Date();_Yl2.setUTCFullYear(\"2003\");if (_Yl2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ZQu0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}