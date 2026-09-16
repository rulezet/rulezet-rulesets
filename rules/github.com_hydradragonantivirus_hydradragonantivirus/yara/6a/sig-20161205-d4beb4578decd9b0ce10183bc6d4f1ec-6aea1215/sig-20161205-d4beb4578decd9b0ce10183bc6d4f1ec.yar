rule sig_20161205_d4beb4578decd9b0ce10183bc6d4f1ec {
  meta:
    description = "datamaliciousorder - file 20161205_d4beb4578decd9b0ce10183bc6d4f1ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d686b383d363b810a5769099bad3845c0b2697eb436e17ee7e2bf3c7461e396"

  strings:
    $s1 = "function _Uw0(s) {var _Sw8 = new Date();_Sw8.setUTCFullYear(\"2003\");if (_Sw8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uw0(s) {var _Sw8 = new Date();_Sw8.setUTCFullYear(\"2003\");if (_Sw8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sq9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}