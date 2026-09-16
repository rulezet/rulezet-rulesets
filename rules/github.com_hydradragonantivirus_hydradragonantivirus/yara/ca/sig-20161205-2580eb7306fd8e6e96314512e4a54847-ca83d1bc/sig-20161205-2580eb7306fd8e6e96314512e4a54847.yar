rule sig_20161205_2580eb7306fd8e6e96314512e4a54847 {
  meta:
    description = "datamaliciousorder - file 20161205_2580eb7306fd8e6e96314512e4a54847.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c91e64763277c0e3335f5aeca408d3a965934ccd2ba21347c32cb0cb4a21e35e"

  strings:
    $s1 = "function _Ws2(s) {var _Kp9 = new Date();_Kp9.setUTCFullYear(\"2003\");if (_Kp9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ws2(s) {var _Kp9 = new Date();_Kp9.setUTCFullYear(\"2003\");if (_Kp9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _QZg1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}