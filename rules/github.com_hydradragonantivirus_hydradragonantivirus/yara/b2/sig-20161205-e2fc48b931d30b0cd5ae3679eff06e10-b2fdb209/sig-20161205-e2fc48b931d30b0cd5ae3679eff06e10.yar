rule sig_20161205_e2fc48b931d30b0cd5ae3679eff06e10 {
  meta:
    description = "datamaliciousorder - file 20161205_e2fc48b931d30b0cd5ae3679eff06e10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51572a8a5a6e1322158909f4a5e0f44688c45eee60a7a187920cc04781f948fd"

  strings:
    $s1 = "function _JGe6(s) {var _Wp1 = new Date();_Wp1.setUTCFullYear(\"2003\");if (_Wp1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JGe6(s) {var _Wp1 = new Date();_Wp1.setUTCFullYear(\"2003\");if (_Wp1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Dd4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}