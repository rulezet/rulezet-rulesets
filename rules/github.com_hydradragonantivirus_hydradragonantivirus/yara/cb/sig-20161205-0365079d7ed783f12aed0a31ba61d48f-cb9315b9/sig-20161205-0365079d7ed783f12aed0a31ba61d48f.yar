rule sig_20161205_0365079d7ed783f12aed0a31ba61d48f {
  meta:
    description = "datamaliciousorder - file 20161205_0365079d7ed783f12aed0a31ba61d48f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fac87f3faab9f60adfdaef65b17c73ad1a0938089924c5ad732eff1e7d3af8c"

  strings:
    $s1 = "function _LVh7(s) {var _Oz5 = new Date();_Oz5.setUTCFullYear(\"2003\");if (_Oz5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LVh7(s) {var _Oz5 = new Date();_Oz5.setUTCFullYear(\"2003\");if (_Oz5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Fd7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}