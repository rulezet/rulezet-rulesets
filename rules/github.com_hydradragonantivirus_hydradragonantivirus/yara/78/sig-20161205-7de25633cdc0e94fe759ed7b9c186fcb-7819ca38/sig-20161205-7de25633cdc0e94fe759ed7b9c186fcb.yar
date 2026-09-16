rule sig_20161205_7de25633cdc0e94fe759ed7b9c186fcb {
  meta:
    description = "datamaliciousorder - file 20161205_7de25633cdc0e94fe759ed7b9c186fcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc43e10d46c32ce1535b7d24ada9772cbeda088d748c7a11bcc074d9808d499b"

  strings:
    $s1 = "function _KMs9(s) {var _Xk0 = new Date();_Xk0.setUTCFullYear(\"2003\");if (_Xk0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KMs9(s) {var _Xk0 = new Date();_Xk0.setUTCFullYear(\"2003\");if (_Xk0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _CXm5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}