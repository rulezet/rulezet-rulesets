rule sig_20161205_61f184d119344d492b85382ce2c89e21 {
  meta:
    description = "datamaliciousorder - file 20161205_61f184d119344d492b85382ce2c89e21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f34c88a4ee5bb8794b3e753e749b0e8cf91bacf8c655fd73f77c2f5a822e0f"

  strings:
    $s1 = "function _Jn5(s) {var _Jm4 = new Date();_Jm4.setUTCFullYear(\"2003\");if (_Jm4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jn5(s) {var _Jm4 = new Date();_Jm4.setUTCFullYear(\"2003\");if (_Jm4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _La4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}