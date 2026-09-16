rule sig_20161205_ee838fbe833d9e5585cb91e08442140a {
  meta:
    description = "datamaliciousorder - file 20161205_ee838fbe833d9e5585cb91e08442140a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04853573293082f3a17cc16ee8cd1b217dd00b1f5d9596d1399850cf219e45ef"

  strings:
    $s1 = "function _LJk7(s) {var _Si4 = new Date();_Si4.setUTCFullYear(\"2003\");if (_Si4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LJk7(s) {var _Si4 = new Date();_Si4.setUTCFullYear(\"2003\");if (_Si4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Mv1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}