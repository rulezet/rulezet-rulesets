rule sig_20161205_da62e0ab6374e4a82fc1e8c4754ed9ec {
  meta:
    description = "datamaliciousorder - file 20161205_da62e0ab6374e4a82fc1e8c4754ed9ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf213362d6ac80ded5c619b7f27f0df5d1160fb531a2a35771d7338b6c56240"

  strings:
    $s1 = "function _KNx0(s) {var _XHm8 = new Date();_XHm8.setUTCFullYear(\"2003\");if (_XHm8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KNx0(s) {var _XHm8 = new Date();_XHm8.setUTCFullYear(\"2003\");if (_XHm8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Rv1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}