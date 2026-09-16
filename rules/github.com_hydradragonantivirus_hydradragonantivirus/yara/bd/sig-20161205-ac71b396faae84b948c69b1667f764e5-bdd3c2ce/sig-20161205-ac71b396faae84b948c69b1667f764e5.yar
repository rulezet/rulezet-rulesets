rule sig_20161205_ac71b396faae84b948c69b1667f764e5 {
  meta:
    description = "datamaliciousorder - file 20161205_ac71b396faae84b948c69b1667f764e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a63169dc3e93d5c52a2f44bf376740aed9175f16dad2d69f6ab0fb0aa4b3a83d"

  strings:
    $s1 = "function _Ei1(s) {var _BRc7 = new Date();_BRc7.setUTCFullYear(\"2003\");if (_BRc7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ei1(s) {var _BRc7 = new Date();_BRc7.setUTCFullYear(\"2003\");if (_BRc7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Du8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}