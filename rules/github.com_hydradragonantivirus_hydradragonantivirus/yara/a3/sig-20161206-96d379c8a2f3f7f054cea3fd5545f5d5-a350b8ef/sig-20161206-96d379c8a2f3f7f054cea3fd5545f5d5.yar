rule sig_20161206_96d379c8a2f3f7f054cea3fd5545f5d5 {
  meta:
    description = "datamaliciousorder - file 20161206_96d379c8a2f3f7f054cea3fd5545f5d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a471cc5681fdc63e94c36865f1e34dd00204b1a5a92ed133a6f6cad5ac43b6e"

  strings:
    $s1 = "function _CBf8(s) {var _JEw8 = new Date();_JEw8.setUTCFullYear(\"2003\");if (_JEw8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CBf8(s) {var _JEw8 = new Date();_JEw8.setUTCFullYear(\"2003\");if (_JEw8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ri3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}