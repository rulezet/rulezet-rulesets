rule sig_20161205_e9dac5cb00d98f31f5a570eb6a25bcc6 {
  meta:
    description = "datamaliciousorder - file 20161205_e9dac5cb00d98f31f5a570eb6a25bcc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73a8f741359752f0a7de52781aa665c778b8885ce824a7facef633545e51b36f"

  strings:
    $s1 = "function _Lb9(s) {var _Rz1 = new Date();_Rz1.setUTCFullYear(\"2003\");if (_Rz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Lb9(s) {var _Rz1 = new Date();_Rz1.setUTCFullYear(\"2003\");if (_Rz1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ou1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}