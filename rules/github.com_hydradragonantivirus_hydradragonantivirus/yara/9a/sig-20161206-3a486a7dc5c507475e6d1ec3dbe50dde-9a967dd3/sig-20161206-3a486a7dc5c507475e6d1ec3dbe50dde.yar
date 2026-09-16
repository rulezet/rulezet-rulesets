rule sig_20161206_3a486a7dc5c507475e6d1ec3dbe50dde {
  meta:
    description = "datamaliciousorder - file 20161206_3a486a7dc5c507475e6d1ec3dbe50dde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e33685e78dfa37030b432131fa591bb596f47218047ca54ee3480c0be0bf1d4"

  strings:
    $s1 = "function _Sa3(s) {var _He6 = new Date();_He6.setUTCFullYear(\"2003\");if (_He6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sa3(s) {var _He6 = new Date();_He6.setUTCFullYear(\"2003\");if (_He6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PNu0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}