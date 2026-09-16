rule sig_20161205_8fd177e422f249a12cbc205928961a4b {
  meta:
    description = "datamaliciousorder - file 20161205_8fd177e422f249a12cbc205928961a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b35224486ff747498369326342b26dbef337acfa27a14ea651904db8124b226f"

  strings:
    $s1 = "function _Ar1(s) {var _AZq2 = new Date();_AZq2.setUTCFullYear(\"2003\");if (_AZq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ar1(s) {var _AZq2 = new Date();_AZq2.setUTCFullYear(\"2003\");if (_AZq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ii8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}