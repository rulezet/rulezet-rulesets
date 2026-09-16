rule sig_20161205_f2e767be08cf383e08f1dcc0043c2fef {
  meta:
    description = "datamaliciousorder - file 20161205_f2e767be08cf383e08f1dcc0043c2fef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "876c0b3743e25078674eaefbbce56cf45333344e7a2cd769f7e11d8c92c4fec1"

  strings:
    $s1 = "function _Vj6(s) {var _SHe5 = new Date();_SHe5.setUTCFullYear(\"2003\");if (_SHe5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vj6(s) {var _SHe5 = new Date();_SHe5.setUTCFullYear(\"2003\");if (_SHe5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FCf4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}