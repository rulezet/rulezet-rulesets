rule sig_20161205_607a297d8fdce1fe100f91e9c51d5368 {
  meta:
    description = "datamaliciousorder - file 20161205_607a297d8fdce1fe100f91e9c51d5368.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96a677b3ce0d27355045f7198bb239198bfffd7426153253383d15fb88604d15"

  strings:
    $s1 = "function _Mx3(s) {var _Rx9 = new Date();_Rx9.setUTCFullYear(\"2003\");if (_Rx9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mx3(s) {var _Rx9 = new Date();_Rx9.setUTCFullYear(\"2003\");if (_Rx9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ss7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}