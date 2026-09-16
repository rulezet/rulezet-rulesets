rule sig_20161206_038b11537ecf4fe65c82ab4a4d6be0ff {
  meta:
    description = "datamaliciousorder - file 20161206_038b11537ecf4fe65c82ab4a4d6be0ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adec2a7a688aaf241418cf220af494230938ac60a8865cb168f5b37ebc903d72"

  strings:
    $s1 = "function _Dj9(s) {var _Xd0 = new Date();_Xd0.setUTCFullYear(\"2003\");if (_Xd0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dj9(s) {var _Xd0 = new Date();_Xd0.setUTCFullYear(\"2003\");if (_Xd0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _FSm5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}