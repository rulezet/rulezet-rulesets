rule sig_20161205_e2c8a0d7806edb8089f5044fdf6a25a0 {
  meta:
    description = "datamaliciousorder - file 20161205_e2c8a0d7806edb8089f5044fdf6a25a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355ce2d870c49d5413b964ff08c03a92aa545f4ccf0ba395e429286868991dd4"

  strings:
    $s1 = "function _GQc5(s) {var _FNk1 = new Date();_FNk1.setUTCFullYear(\"2003\");if (_FNk1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GQc5(s) {var _FNk1 = new Date();_FNk1.setUTCFullYear(\"2003\");if (_FNk1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _GSm4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}