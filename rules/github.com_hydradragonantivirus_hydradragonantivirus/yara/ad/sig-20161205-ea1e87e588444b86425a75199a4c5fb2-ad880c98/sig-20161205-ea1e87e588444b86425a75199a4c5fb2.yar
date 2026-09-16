rule sig_20161205_ea1e87e588444b86425a75199a4c5fb2 {
  meta:
    description = "datamaliciousorder - file 20161205_ea1e87e588444b86425a75199a4c5fb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c215216554fc1b2d558235152c0b69024891bdaa8fd89a54d2c5663b2d3ccb4"

  strings:
    $s1 = "function _Hj4(s) {var _Ol0 = new Date();_Ol0.setUTCFullYear(\"2003\");if (_Ol0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hj4(s) {var _Ol0 = new Date();_Ol0.setUTCFullYear(\"2003\");if (_Ol0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _DZa7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}