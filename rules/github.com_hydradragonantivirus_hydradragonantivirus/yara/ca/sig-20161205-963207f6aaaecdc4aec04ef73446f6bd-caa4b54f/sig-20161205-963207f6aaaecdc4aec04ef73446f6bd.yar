rule sig_20161205_963207f6aaaecdc4aec04ef73446f6bd {
  meta:
    description = "datamaliciousorder - file 20161205_963207f6aaaecdc4aec04ef73446f6bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40df42d68ab52d236e29187ad6def34dc2d061b1efd6b0d0bc12fd9e92cf7df4"

  strings:
    $s1 = "function _Im2(s) {var _Gq2 = new Date();_Gq2.setUTCFullYear(\"2003\");if (_Gq2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Im2(s) {var _Gq2 = new Date();_Gq2.setUTCFullYear(\"2003\");if (_Gq2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MFy6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}