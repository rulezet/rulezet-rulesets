rule sig_20161206_6337fc6af1877e38c1f6b00ceaf0af10 {
  meta:
    description = "datamaliciousorder - file 20161206_6337fc6af1877e38c1f6b00ceaf0af10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e74e16302d3c9fce0a8d2e2a75c016619579a43fd4170dcf2a0fbf9611f5e4e"

  strings:
    $s1 = "function _Sy5(s) {var _LFe1 = new Date();_LFe1.setUTCFullYear(\"2003\");if (_LFe1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sy5(s) {var _LFe1 = new Date();_LFe1.setUTCFullYear(\"2003\");if (_LFe1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _WHu8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}