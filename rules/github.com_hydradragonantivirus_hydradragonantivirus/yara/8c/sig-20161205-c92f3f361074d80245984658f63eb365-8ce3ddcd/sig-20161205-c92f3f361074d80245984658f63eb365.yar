rule sig_20161205_c92f3f361074d80245984658f63eb365 {
  meta:
    description = "datamaliciousorder - file 20161205_c92f3f361074d80245984658f63eb365.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf5b3cc6900b437480a7cfccd2774a62bc50558e77194e48474ced17f7b271f"

  strings:
    $s1 = "function _Ex7(s) {var _Gm0 = new Date();_Gm0.setUTCFullYear(\"2003\");if (_Gm0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ex7(s) {var _Gm0 = new Date();_Gm0.setUTCFullYear(\"2003\");if (_Gm0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Oy9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}