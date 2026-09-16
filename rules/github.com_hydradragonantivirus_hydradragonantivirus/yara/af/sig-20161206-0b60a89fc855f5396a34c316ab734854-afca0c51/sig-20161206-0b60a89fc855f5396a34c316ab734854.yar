rule sig_20161206_0b60a89fc855f5396a34c316ab734854 {
  meta:
    description = "datamaliciousorder - file 20161206_0b60a89fc855f5396a34c316ab734854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58c69c9eba031c0ac6c2cfdf9c3b4ed3cb9837ca6d796906aaa0b5580d29998e"

  strings:
    $s1 = "function _NZp0(s) {var _NFl1 = new Date();_NFl1.setUTCFullYear(\"2003\");if (_NFl1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NZp0(s) {var _NFl1 = new Date();_NFl1.setUTCFullYear(\"2003\");if (_NFl1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WTr0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}