rule sig_20161205_bf00ab8a5a0fa57e91c63c709eab2da9 {
  meta:
    description = "datamaliciousorder - file 20161205_bf00ab8a5a0fa57e91c63c709eab2da9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12af1f9b1bc262b7224b7aac3f8aba301954292036cd181fb86c53b1a6e96099"

  strings:
    $s1 = "function _JGi0(s) {var _Aw8 = new Date();_Aw8.setUTCFullYear(\"2003\");if (_Aw8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JGi0(s) {var _Aw8 = new Date();_Aw8.setUTCFullYear(\"2003\");if (_Aw8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FJv0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}