rule sig_20161205_d435146e6515dcc4f079707beb1cc5e2 {
  meta:
    description = "datamaliciousorder - file 20161205_d435146e6515dcc4f079707beb1cc5e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb57e2a248044e8ad98aec673a52702aa72d0e0b635cad7d9c8a036555f9d855"

  strings:
    $s1 = "function _Io5(s) {var _Hd3 = new Date();_Hd3.setUTCFullYear(\"2003\");if (_Hd3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Io5(s) {var _Hd3 = new Date();_Hd3.setUTCFullYear(\"2003\");if (_Hd3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MMt8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}