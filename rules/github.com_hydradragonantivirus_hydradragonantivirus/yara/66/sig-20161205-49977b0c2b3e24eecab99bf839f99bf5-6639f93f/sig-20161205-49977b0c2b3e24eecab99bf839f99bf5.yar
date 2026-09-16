rule sig_20161205_49977b0c2b3e24eecab99bf839f99bf5 {
  meta:
    description = "datamaliciousorder - file 20161205_49977b0c2b3e24eecab99bf839f99bf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9696dd3c150125fd284293555bab8ec1257a0c89f65b162378abf05963d2db0b"

  strings:
    $s1 = "function _Ba1(s) {var _SHv6 = new Date();_SHv6.setUTCFullYear(\"2003\");if (_SHv6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ba1(s) {var _SHv6 = new Date();_SHv6.setUTCFullYear(\"2003\");if (_SHv6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _BOr5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}