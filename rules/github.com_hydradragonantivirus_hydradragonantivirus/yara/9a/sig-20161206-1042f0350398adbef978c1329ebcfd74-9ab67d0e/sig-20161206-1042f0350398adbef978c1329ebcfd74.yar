rule sig_20161206_1042f0350398adbef978c1329ebcfd74 {
  meta:
    description = "datamaliciousorder - file 20161206_1042f0350398adbef978c1329ebcfd74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d79203be299059fb81ace8dc4ec631cecfda5b5e2efc3e2d319d30a0cd86a755"

  strings:
    $s1 = "function _Tz6(s) {var _NCl1 = new Date();_NCl1.setUTCFullYear(\"2003\");if (_NCl1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tz6(s) {var _NCl1 = new Date();_NCl1.setUTCFullYear(\"2003\");if (_NCl1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YJk2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}