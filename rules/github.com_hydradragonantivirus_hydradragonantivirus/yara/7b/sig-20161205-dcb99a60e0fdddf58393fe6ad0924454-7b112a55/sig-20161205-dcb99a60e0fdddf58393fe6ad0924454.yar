rule sig_20161205_dcb99a60e0fdddf58393fe6ad0924454 {
  meta:
    description = "datamaliciousorder - file 20161205_dcb99a60e0fdddf58393fe6ad0924454.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0622014b97b151f672b9be3fe0f681e6b12ab8f994c466e7b86645eb951f9a1"

  strings:
    $s1 = "function _JRt9(s) {var _Qa4 = new Date();_Qa4.setUTCFullYear(\"2003\");if (_Qa4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JRt9(s) {var _Qa4 = new Date();_Qa4.setUTCFullYear(\"2003\");if (_Qa4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GSk6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}