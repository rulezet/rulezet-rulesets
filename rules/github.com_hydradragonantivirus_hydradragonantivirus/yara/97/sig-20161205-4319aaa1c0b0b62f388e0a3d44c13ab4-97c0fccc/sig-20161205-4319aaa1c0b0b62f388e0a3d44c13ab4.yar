rule sig_20161205_4319aaa1c0b0b62f388e0a3d44c13ab4 {
  meta:
    description = "datamaliciousorder - file 20161205_4319aaa1c0b0b62f388e0a3d44c13ab4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de64c77ac87da12e63fc930b741d11a97117832f06171e52518c8247ec63186e"

  strings:
    $s1 = "function _YCh1(s) {var _Ib2 = new Date();_Ib2.setUTCFullYear(\"2003\");if (_Ib2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YCh1(s) {var _Ib2 = new Date();_Ib2.setUTCFullYear(\"2003\");if (_Ib2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _AUb0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}