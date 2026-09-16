rule sig_20161205_a736214f22fbabd64e17184fbf81067b {
  meta:
    description = "datamaliciousorder - file 20161205_a736214f22fbabd64e17184fbf81067b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "930d7a294785a4e9afd0e1ee3b08c94fbab1b5581d3462ec1750044a00f4f7d9"

  strings:
    $s1 = "function _Me2(s) {var _WJn2 = new Date();_WJn2.setUTCFullYear(\"2003\");if (_WJn2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Me2(s) {var _WJn2 = new Date();_WJn2.setUTCFullYear(\"2003\");if (_WJn2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Hm6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}