rule sig_20161205_e63dbd2130f1e66d4e138eb95b8e1e67 {
  meta:
    description = "datamaliciousorder - file 20161205_e63dbd2130f1e66d4e138eb95b8e1e67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a0f0bafff75e1c7cee54abb4b57f7a1b9acad9efbb2877a58ca7e76789ed08e"

  strings:
    $s1 = "function _HSt0(s) {var _YBf9 = new Date();_YBf9.setUTCFullYear(\"2003\");if (_YBf9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HSt0(s) {var _YBf9 = new Date();_YBf9.setUTCFullYear(\"2003\");if (_YBf9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Zz7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}