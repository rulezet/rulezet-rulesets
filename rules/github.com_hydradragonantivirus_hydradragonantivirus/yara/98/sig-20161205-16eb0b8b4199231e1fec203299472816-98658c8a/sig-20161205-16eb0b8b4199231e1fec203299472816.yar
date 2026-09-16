rule sig_20161205_16eb0b8b4199231e1fec203299472816 {
  meta:
    description = "datamaliciousorder - file 20161205_16eb0b8b4199231e1fec203299472816.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03b761aaf304c4ba95bdea4c697ccc3c18531cd22133572d20f515b817897e41"

  strings:
    $s1 = "function _Sj4(s) {var _Vs2 = new Date();_Vs2.setUTCFullYear(\"2003\");if (_Vs2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sj4(s) {var _Vs2 = new Date();_Vs2.setUTCFullYear(\"2003\");if (_Vs2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QEz5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}