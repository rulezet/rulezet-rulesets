rule sig_20161205_a864c97dedcb6e5cb342e27172cf1158 {
  meta:
    description = "datamaliciousorder - file 20161205_a864c97dedcb6e5cb342e27172cf1158.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52bbafed291d9dc07058dcf6296d8f38fb4ade6c2d66658a9a8dc06f57ea3361"

  strings:
    $s1 = "function _Oy9(s) {var _Pv5 = new Date();_Pv5.setUTCFullYear(\"2003\");if (_Pv5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Oy9(s) {var _Pv5 = new Date();_Pv5.setUTCFullYear(\"2003\");if (_Pv5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HRy0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}