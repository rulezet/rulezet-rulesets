rule sig_20161205_fe97e3cca58398319524d04e319ad618 {
  meta:
    description = "datamaliciousorder - file 20161205_fe97e3cca58398319524d04e319ad618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "772f35386f7f82346e476083e18e9e3d8094f052c45290615725b828d22a6a3e"

  strings:
    $s1 = "function _Jt1(s) {var _XYf6 = new Date();_XYf6.setUTCFullYear(\"2003\");if (_XYf6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jt1(s) {var _XYf6 = new Date();_XYf6.setUTCFullYear(\"2003\");if (_XYf6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ACm7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}