rule sig_20161206_0526ccef4d5221b3ca292346e0ba8e6d {
  meta:
    description = "datamaliciousorder - file 20161206_0526ccef4d5221b3ca292346e0ba8e6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b33f776bb311cbb5fb6bbb2a25b9c238be6e0f454556fbd125c41c31ac1033a"

  strings:
    $s1 = "function _WDp7(s) {var _En7 = new Date();_En7.setUTCFullYear(\"2003\");if (_En7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _WDp7(s) {var _En7 = new Date();_En7.setUTCFullYear(\"2003\");if (_En7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _SDv5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}