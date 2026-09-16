rule sig_20161206_8fc5237228fce748419d98255071aac9 {
  meta:
    description = "datamaliciousorder - file 20161206_8fc5237228fce748419d98255071aac9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "138b57a2b00944b74a73d67cb99b953095d01fa1dca4e065f6a5753042aad2f0"

  strings:
    $s1 = "function _IJs5(s) {var _BFn6 = new Date();_BFn6.setUTCFullYear(\"2003\");if (_BFn6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IJs5(s) {var _BFn6 = new Date();_BFn6.setUTCFullYear(\"2003\");if (_BFn6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _AVe5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}