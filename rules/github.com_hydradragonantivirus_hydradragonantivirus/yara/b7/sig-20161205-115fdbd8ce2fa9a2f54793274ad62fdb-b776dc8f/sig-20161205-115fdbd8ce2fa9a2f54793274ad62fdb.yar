rule sig_20161205_115fdbd8ce2fa9a2f54793274ad62fdb {
  meta:
    description = "datamaliciousorder - file 20161205_115fdbd8ce2fa9a2f54793274ad62fdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5125ef0559e781c529c111b4a4cafc83f314d9e877463f5a28cb478bdda5af3"

  strings:
    $s1 = "function _Tj7(s) {var _XCp0 = new Date();_XCp0.setUTCFullYear(\"2003\");if (_XCp0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tj7(s) {var _XCp0 = new Date();_XCp0.setUTCFullYear(\"2003\");if (_XCp0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _WDl9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}