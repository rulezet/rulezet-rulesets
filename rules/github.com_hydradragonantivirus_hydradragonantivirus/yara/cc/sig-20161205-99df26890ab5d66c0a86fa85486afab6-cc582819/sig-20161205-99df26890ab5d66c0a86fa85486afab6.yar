rule sig_20161205_99df26890ab5d66c0a86fa85486afab6 {
  meta:
    description = "datamaliciousorder - file 20161205_99df26890ab5d66c0a86fa85486afab6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5745bbd6043586e348cb2efa6b1feb65713cc5e9b88522d6215e030af9c2d241"

  strings:
    $s1 = "function _TGw8(s) {var _CFb0 = new Date();_CFb0.setUTCFullYear(\"2003\");if (_CFb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TGw8(s) {var _CFb0 = new Date();_CFb0.setUTCFullYear(\"2003\");if (_CFb0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Cp9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}