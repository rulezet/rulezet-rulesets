rule sig_20161205_55ec13b48bfbeb81d27748194be70ff5 {
  meta:
    description = "datamaliciousorder - file 20161205_55ec13b48bfbeb81d27748194be70ff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a8846d68287e269c40a7bb55b3e9b5450e9acf9d647dd4d8edd16db90d96e53"

  strings:
    $s1 = "function _Wo6(s) {var _LJm0 = new Date();_LJm0.setUTCFullYear(\"2003\");if (_LJm0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Wo6(s) {var _LJm0 = new Date();_LJm0.setUTCFullYear(\"2003\");if (_LJm0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Tg1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}