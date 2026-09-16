rule sig_20161205_37d23ef8dac2ebce2b3477696bdb4bbb {
  meta:
    description = "datamaliciousorder - file 20161205_37d23ef8dac2ebce2b3477696bdb4bbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba1cb06e5df7da3157024b0f3fb27c9323a682c42e8ac3f34c5a0d62dd65959"

  strings:
    $s1 = "function _Ed3(s) {var _Gg3 = new Date();_Gg3.setUTCFullYear(\"2003\");if (_Gg3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ed3(s) {var _Gg3 = new Date();_Gg3.setUTCFullYear(\"2003\");if (_Gg3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _BLy7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}