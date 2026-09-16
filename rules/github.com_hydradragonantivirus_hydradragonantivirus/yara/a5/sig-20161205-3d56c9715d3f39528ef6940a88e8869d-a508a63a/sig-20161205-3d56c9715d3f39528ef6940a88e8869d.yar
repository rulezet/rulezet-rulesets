rule sig_20161205_3d56c9715d3f39528ef6940a88e8869d {
  meta:
    description = "datamaliciousorder - file 20161205_3d56c9715d3f39528ef6940a88e8869d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7677febf47ca18acb32c7c32f395f813b49bc0c1c92587cbc4f2f9c706ec60"

  strings:
    $s1 = "function _HJd0(s) {var _Yu1 = new Date();_Yu1.setUTCFullYear(\"2003\");if (_Yu1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HJd0(s) {var _Yu1 = new Date();_Yu1.setUTCFullYear(\"2003\");if (_Yu1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ICe0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}