rule sig_20161205_241424dfb88f6c5ea4395dc534d7f506 {
  meta:
    description = "datamaliciousorder - file 20161205_241424dfb88f6c5ea4395dc534d7f506.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b27a3427842b367bfc429152eaefd03d92fd0d16eaafed336420837030ab29e"

  strings:
    $s1 = "function _Sj3(s) {var _SSi8 = new Date();_SSi8.setUTCFullYear(\"2003\");if (_SSi8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sj3(s) {var _SSi8 = new Date();_SSi8.setUTCFullYear(\"2003\");if (_SSi8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FKd3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}