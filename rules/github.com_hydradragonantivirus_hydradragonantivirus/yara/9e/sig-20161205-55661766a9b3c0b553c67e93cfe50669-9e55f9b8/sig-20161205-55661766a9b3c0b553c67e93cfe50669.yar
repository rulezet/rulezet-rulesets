rule sig_20161205_55661766a9b3c0b553c67e93cfe50669 {
  meta:
    description = "datamaliciousorder - file 20161205_55661766a9b3c0b553c67e93cfe50669.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87ecfe334f27096942a3f1a03bc2c36932e79364d56012e8e35c8cdbc4412042"

  strings:
    $s1 = "function _SOa9(s) {var _Qd3 = new Date();_Qd3.setUTCFullYear(\"2003\");if (_Qd3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SOa9(s) {var _Qd3 = new Date();_Qd3.setUTCFullYear(\"2003\");if (_Qd3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _OJj3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}