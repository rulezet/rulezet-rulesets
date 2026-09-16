rule sig_20161205_bd9e700034e9f47651de4939aa3901e0 {
  meta:
    description = "datamaliciousorder - file 20161205_bd9e700034e9f47651de4939aa3901e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bab8247c9df6b046aaea33ab18346a303f3d2c1bbc0b4070af6ae50c9b96b509"

  strings:
    $s1 = "function _UWn8(s) {var _Wv5 = new Date();_Wv5.setUTCFullYear(\"2003\");if (_Wv5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UWn8(s) {var _Wv5 = new Date();_Wv5.setUTCFullYear(\"2003\");if (_Wv5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _IIl0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}