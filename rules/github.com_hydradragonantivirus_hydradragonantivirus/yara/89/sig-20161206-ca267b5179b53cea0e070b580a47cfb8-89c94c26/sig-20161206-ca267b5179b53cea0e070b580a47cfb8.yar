rule sig_20161206_ca267b5179b53cea0e070b580a47cfb8 {
  meta:
    description = "datamaliciousorder - file 20161206_ca267b5179b53cea0e070b580a47cfb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01d67e3bd967fbd0e73a83ad31a6f7ef5869ff334e57bf190c77ab72d9c6d6b8"

  strings:
    $s1 = "function _Un1(s) {var _Tl9 = new Date();_Tl9.setUTCFullYear(\"2003\");if (_Tl9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Un1(s) {var _Tl9 = new Date();_Tl9.setUTCFullYear(\"2003\");if (_Tl9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PGx9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}