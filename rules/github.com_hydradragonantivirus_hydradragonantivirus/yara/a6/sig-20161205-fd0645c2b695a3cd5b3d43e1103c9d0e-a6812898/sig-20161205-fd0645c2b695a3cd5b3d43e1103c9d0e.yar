rule sig_20161205_fd0645c2b695a3cd5b3d43e1103c9d0e {
  meta:
    description = "datamaliciousorder - file 20161205_fd0645c2b695a3cd5b3d43e1103c9d0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35715d6e23c777945a23228f251545987ad76beab4a96febd1cdd99fc6ae1017"

  strings:
    $s1 = "function _AZh0(s) {var _Ym4 = new Date();_Ym4.setUTCFullYear(\"2003\");if (_Ym4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AZh0(s) {var _Ym4 = new Date();_Ym4.setUTCFullYear(\"2003\");if (_Ym4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Aq8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}