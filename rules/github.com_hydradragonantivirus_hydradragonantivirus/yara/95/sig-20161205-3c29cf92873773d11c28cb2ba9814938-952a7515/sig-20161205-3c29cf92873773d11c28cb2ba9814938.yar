rule sig_20161205_3c29cf92873773d11c28cb2ba9814938 {
  meta:
    description = "datamaliciousorder - file 20161205_3c29cf92873773d11c28cb2ba9814938.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18af1906ca4e3c90ec712cc6903ff45da59a57f1606c7cf4cc9476ad8c1a3f57"

  strings:
    $s1 = "function _Kj3(s) {var _Ow8 = new Date();_Ow8.setUTCFullYear(\"2003\");if (_Ow8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kj3(s) {var _Ow8 = new Date();_Ow8.setUTCFullYear(\"2003\");if (_Ow8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _WNp9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}