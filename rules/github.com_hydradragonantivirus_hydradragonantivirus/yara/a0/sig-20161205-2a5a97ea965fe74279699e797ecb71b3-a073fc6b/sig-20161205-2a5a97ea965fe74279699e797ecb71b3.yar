rule sig_20161205_2a5a97ea965fe74279699e797ecb71b3 {
  meta:
    description = "datamaliciousorder - file 20161205_2a5a97ea965fe74279699e797ecb71b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bab3a6bf1a04610b513aa97e3d29ae55be1a10d692c40ff2f23685ad03a2419"

  strings:
    $s1 = "function _Qg1(s) {var _HVw6 = new Date();_HVw6.setUTCFullYear(\"2003\");if (_HVw6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qg1(s) {var _HVw6 = new Date();_HVw6.setUTCFullYear(\"2003\");if (_HVw6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Cc5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}