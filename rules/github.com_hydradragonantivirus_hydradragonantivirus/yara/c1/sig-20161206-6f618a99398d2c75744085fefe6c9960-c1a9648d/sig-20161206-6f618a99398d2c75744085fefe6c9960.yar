rule sig_20161206_6f618a99398d2c75744085fefe6c9960 {
  meta:
    description = "datamaliciousorder - file 20161206_6f618a99398d2c75744085fefe6c9960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c5938d8754b0135e6d89dde10d7818623ac888c36c8dccb141efef75df5cff"

  strings:
    $s1 = "function _Uk4(s) {var _MXf7 = new Date();_MXf7.setUTCFullYear(\"2003\");if (_MXf7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Uk4(s) {var _MXf7 = new Date();_MXf7.setUTCFullYear(\"2003\");if (_MXf7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _TWn9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}