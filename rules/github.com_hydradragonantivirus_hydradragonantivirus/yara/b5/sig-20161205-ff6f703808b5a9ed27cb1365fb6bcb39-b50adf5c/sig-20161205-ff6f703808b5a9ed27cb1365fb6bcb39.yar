rule sig_20161205_ff6f703808b5a9ed27cb1365fb6bcb39 {
  meta:
    description = "datamaliciousorder - file 20161205_ff6f703808b5a9ed27cb1365fb6bcb39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a4c7c51d00ea7b2471176454ad4f0ed1326db944d97d2c841e9aabbbb5f487"

  strings:
    $s1 = "function _Ok9(s) {var _Kw4 = new Date();_Kw4.setUTCFullYear(\"2003\");if (_Kw4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ok9(s) {var _Kw4 = new Date();_Kw4.setUTCFullYear(\"2003\");if (_Kw4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _YYq6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}