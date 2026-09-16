rule sig_20161205_dd23c6d92fef4313a8f6d928c590e4a8 {
  meta:
    description = "datamaliciousorder - file 20161205_dd23c6d92fef4313a8f6d928c590e4a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d2617769b513aecc4b0e26dd60f7f2e3ecd00b9d6a6b88d065edd8c73da7f5c"

  strings:
    $s1 = "function _Oc0(s) {var _DKx7 = new Date();_DKx7.setUTCFullYear(\"2003\");if (_DKx7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Oc0(s) {var _DKx7 = new Date();_DKx7.setUTCFullYear(\"2003\");if (_DKx7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MKf0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}