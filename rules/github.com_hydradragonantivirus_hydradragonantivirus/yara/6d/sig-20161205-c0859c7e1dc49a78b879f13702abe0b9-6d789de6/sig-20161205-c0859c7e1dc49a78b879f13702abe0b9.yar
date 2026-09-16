rule sig_20161205_c0859c7e1dc49a78b879f13702abe0b9 {
  meta:
    description = "datamaliciousorder - file 20161205_c0859c7e1dc49a78b879f13702abe0b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d71820cdcadc85c891c3ac20fb5c3470a3b7beac6e24c572783d4bc0557842"

  strings:
    $s1 = "function _Pb9(s) {var _Ro3 = new Date();_Ro3.setUTCFullYear(\"2003\");if (_Ro3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pb9(s) {var _Ro3 = new Date();_Ro3.setUTCFullYear(\"2003\");if (_Ro3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _CNq0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}