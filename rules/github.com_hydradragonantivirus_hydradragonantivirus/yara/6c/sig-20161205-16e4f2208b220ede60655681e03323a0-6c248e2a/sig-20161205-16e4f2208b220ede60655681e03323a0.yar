rule sig_20161205_16e4f2208b220ede60655681e03323a0 {
  meta:
    description = "datamaliciousorder - file 20161205_16e4f2208b220ede60655681e03323a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bffcabcad7e1aa0823f0554f3ca4e4ab6a5f052b35dae23462487bc5c05a8576"

  strings:
    $s1 = "function _Sj1(s) {var _BAi8 = new Date();_BAi8.setUTCFullYear(\"2003\");if (_BAi8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sj1(s) {var _BAi8 = new Date();_BAi8.setUTCFullYear(\"2003\");if (_BAi8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _IOq8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}