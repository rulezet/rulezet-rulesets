rule sig_20161205_aa530b33b60f03d80de7da967ce7a8c1 {
  meta:
    description = "datamaliciousorder - file 20161205_aa530b33b60f03d80de7da967ce7a8c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28d1251c1398b9426870edaff4d72f7b61689aef3d57ad041796af247aa8491c"

  strings:
    $s1 = "function _QOi4(s) {var _QDl3 = new Date();_QDl3.setUTCFullYear(\"2003\");if (_QDl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QOi4(s) {var _QDl3 = new Date();_QDl3.setUTCFullYear(\"2003\");if (_QDl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VUw0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}