rule sig_20161205_e4a80fe1dcf0f7e3a9cb5ebfd027c115 {
  meta:
    description = "datamaliciousorder - file 20161205_e4a80fe1dcf0f7e3a9cb5ebfd027c115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfc9a840db2ea814739f220bdaa2edc18f2fdcb350a40646bdc144ea7b559b9f"

  strings:
    $s1 = "function _Ye7(s) {var _Ra9 = new Date();_Ra9.setUTCFullYear(\"2003\");if (_Ra9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ye7(s) {var _Ra9 = new Date();_Ra9.setUTCFullYear(\"2003\");if (_Ra9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _IHi6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}