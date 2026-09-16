rule sig_20161205_cce80910473dc3726a0f53da710df183 {
  meta:
    description = "datamaliciousorder - file 20161205_cce80910473dc3726a0f53da710df183.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c32c5ec4934ec8421f7bfd23db61c7d7d3441d2a1a7d5e25a956952842995829"

  strings:
    $s1 = "function _DPe1(s) {var _KZb8 = new Date();_KZb8.setUTCFullYear(\"2003\");if (_KZb8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DPe1(s) {var _KZb8 = new Date();_KZb8.setUTCFullYear(\"2003\");if (_KZb8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WAn9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}