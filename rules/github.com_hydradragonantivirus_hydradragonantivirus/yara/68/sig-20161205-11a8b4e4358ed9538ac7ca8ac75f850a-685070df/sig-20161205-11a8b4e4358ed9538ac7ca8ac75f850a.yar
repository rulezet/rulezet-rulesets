rule sig_20161205_11a8b4e4358ed9538ac7ca8ac75f850a {
  meta:
    description = "datamaliciousorder - file 20161205_11a8b4e4358ed9538ac7ca8ac75f850a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "660a545d6f288a0681adae7bd185f91076eb7f7b45522b6e8177a59dd16f85cc"

  strings:
    $s1 = "function _RZo6(s) {var _Wp6 = new Date();_Wp6.setUTCFullYear(\"2003\");if (_Wp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _RZo6(s) {var _Wp6 = new Date();_Wp6.setUTCFullYear(\"2003\");if (_Wp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Qp6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}