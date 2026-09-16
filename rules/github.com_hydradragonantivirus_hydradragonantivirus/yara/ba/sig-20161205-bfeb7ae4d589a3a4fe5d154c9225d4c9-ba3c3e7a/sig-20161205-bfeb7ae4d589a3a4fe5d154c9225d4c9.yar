rule sig_20161205_bfeb7ae4d589a3a4fe5d154c9225d4c9 {
  meta:
    description = "datamaliciousorder - file 20161205_bfeb7ae4d589a3a4fe5d154c9225d4c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47c901148c997462c7a4a4c4a0bdb7908eb4dc402b76e40b4a793641ad6e9c77"

  strings:
    $s1 = "function _Qs2(s) {var _PNc4 = new Date();_PNc4.setUTCFullYear(\"2003\");if (_PNc4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qs2(s) {var _PNc4 = new Date();_PNc4.setUTCFullYear(\"2003\");if (_PNc4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Vb9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}