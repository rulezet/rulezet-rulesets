rule sig_20161205_aa6051db91dd1b10ec243f35a9ff514e {
  meta:
    description = "datamaliciousorder - file 20161205_aa6051db91dd1b10ec243f35a9ff514e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c896f524b55811d8ed0179e3cd69c11ad1fd1ce79f4eb54d10972ab8b996f7c5"

  strings:
    $s1 = "function _EEt8(s) {var _JTg9 = new Date();_JTg9.setUTCFullYear(\"2003\");if (_JTg9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EEt8(s) {var _JTg9 = new Date();_JTg9.setUTCFullYear(\"2003\");if (_JTg9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _NDo6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}