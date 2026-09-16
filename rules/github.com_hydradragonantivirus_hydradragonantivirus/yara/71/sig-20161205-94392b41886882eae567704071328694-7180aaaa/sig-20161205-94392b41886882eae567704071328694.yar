rule sig_20161205_94392b41886882eae567704071328694 {
  meta:
    description = "datamaliciousorder - file 20161205_94392b41886882eae567704071328694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8758f8414e002568ca5872b1677f26a238ef8dd7e10840c9b23b296c86ff9f13"

  strings:
    $s1 = "function _An8(s) {var _Fv6 = new Date();_Fv6.setUTCFullYear(\"2003\");if (_Fv6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _An8(s) {var _Fv6 = new Date();_Fv6.setUTCFullYear(\"2003\");if (_Fv6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _UOv3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}