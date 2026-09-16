rule sig_20161205_d39fd8bd928d327c474bdae1e5d39c73 {
  meta:
    description = "datamaliciousorder - file 20161205_d39fd8bd928d327c474bdae1e5d39c73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3988a734b5976c9334022e10edc45ca1800993549f10d5fe576aceb41c98c6"

  strings:
    $s1 = "function _Ux7(s) {var _QZo6 = new Date();_QZo6.setUTCFullYear(\"2003\");if (_QZo6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ux7(s) {var _QZo6 = new Date();_QZo6.setUTCFullYear(\"2003\");if (_QZo6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _URl6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}