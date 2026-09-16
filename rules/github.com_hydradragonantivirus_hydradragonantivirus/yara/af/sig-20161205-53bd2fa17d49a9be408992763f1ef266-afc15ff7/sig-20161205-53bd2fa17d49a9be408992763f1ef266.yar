rule sig_20161205_53bd2fa17d49a9be408992763f1ef266 {
  meta:
    description = "datamaliciousorder - file 20161205_53bd2fa17d49a9be408992763f1ef266.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "261da536f3190e7d544991afd13e009cb27bb21793e5a4ffa060684040bcc7f6"

  strings:
    $s1 = "function _An5(s) {var _DFu1 = new Date();_DFu1.setUTCFullYear(\"2003\");if (_DFu1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _An5(s) {var _DFu1 = new Date();_DFu1.setUTCFullYear(\"2003\");if (_DFu1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Nw7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}