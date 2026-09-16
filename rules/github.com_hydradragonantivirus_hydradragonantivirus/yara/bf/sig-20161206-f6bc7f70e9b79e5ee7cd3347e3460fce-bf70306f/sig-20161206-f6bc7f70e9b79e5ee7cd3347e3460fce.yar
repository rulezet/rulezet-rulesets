rule sig_20161206_f6bc7f70e9b79e5ee7cd3347e3460fce {
  meta:
    description = "datamaliciousorder - file 20161206_f6bc7f70e9b79e5ee7cd3347e3460fce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e22a2d6bc10c97faf71be48a700f59f682e7efa2135288816b218cfc6343a17d"

  strings:
    $s1 = "function _NHw1(s) {var _RKe6 = new Date();_RKe6.setUTCFullYear(\"2003\");if (_RKe6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NHw1(s) {var _RKe6 = new Date();_RKe6.setUTCFullYear(\"2003\");if (_RKe6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BCe0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}