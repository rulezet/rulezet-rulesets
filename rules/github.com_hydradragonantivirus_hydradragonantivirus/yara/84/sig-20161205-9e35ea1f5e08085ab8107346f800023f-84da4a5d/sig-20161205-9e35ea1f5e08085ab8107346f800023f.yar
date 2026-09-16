rule sig_20161205_9e35ea1f5e08085ab8107346f800023f {
  meta:
    description = "datamaliciousorder - file 20161205_9e35ea1f5e08085ab8107346f800023f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62f35f50ffb49b29c6c23a19f62ff7d449402ebd0e90e0f8b33a46ea2aeeb0b1"

  strings:
    $s1 = "function _AMe5(s) {var _Dl7 = new Date();_Dl7.setUTCFullYear(\"2003\");if (_Dl7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AMe5(s) {var _Dl7 = new Date();_Dl7.setUTCFullYear(\"2003\");if (_Dl7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Qk1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}