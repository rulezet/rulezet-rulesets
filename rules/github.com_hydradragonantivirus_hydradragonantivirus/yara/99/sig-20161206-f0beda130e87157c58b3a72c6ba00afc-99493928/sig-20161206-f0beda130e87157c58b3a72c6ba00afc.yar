rule sig_20161206_f0beda130e87157c58b3a72c6ba00afc {
  meta:
    description = "datamaliciousorder - file 20161206_f0beda130e87157c58b3a72c6ba00afc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "546d1f0fcdb084708aa6765cfc72196e91771b86da0206b8baf6aeb4d1bcaa3d"

  strings:
    $s1 = "function _YCv0(s) {var _XIm7 = new Date();_XIm7.setUTCFullYear(\"2003\");if (_XIm7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YCv0(s) {var _XIm7 = new Date();_XIm7.setUTCFullYear(\"2003\");if (_XIm7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ot5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}