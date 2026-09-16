rule sig_20161206_04d330219051d87078742574250e0287 {
  meta:
    description = "datamaliciousorder - file 20161206_04d330219051d87078742574250e0287.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f92149f018dc0eb609745083ea8dffee860dafe6a0e5a334af15414d2ef0fef5"

  strings:
    $s1 = "function _Kj6(s) {var _CZe2 = new Date();_CZe2.setUTCFullYear(\"2003\");if (_CZe2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kj6(s) {var _CZe2 = new Date();_CZe2.setUTCFullYear(\"2003\");if (_CZe2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Yy3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}