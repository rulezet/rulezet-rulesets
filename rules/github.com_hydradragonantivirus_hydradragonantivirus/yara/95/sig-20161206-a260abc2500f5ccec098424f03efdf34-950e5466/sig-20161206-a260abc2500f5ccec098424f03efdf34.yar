rule sig_20161206_a260abc2500f5ccec098424f03efdf34 {
  meta:
    description = "datamaliciousorder - file 20161206_a260abc2500f5ccec098424f03efdf34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcdaf2cbbad8cf62410c64e3b9ffda102d1e61d7eb02da8e62b93795b4f170c7"

  strings:
    $s1 = "function _Eg4(s) {var _QEc7 = new Date();_QEc7.setUTCFullYear(\"2003\");if (_QEc7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Eg4(s) {var _QEc7 = new Date();_QEc7.setUTCFullYear(\"2003\");if (_QEc7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DXw6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}