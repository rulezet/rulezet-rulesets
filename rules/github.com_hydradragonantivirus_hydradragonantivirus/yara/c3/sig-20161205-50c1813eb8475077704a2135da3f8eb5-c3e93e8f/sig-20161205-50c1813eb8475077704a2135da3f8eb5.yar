rule sig_20161205_50c1813eb8475077704a2135da3f8eb5 {
  meta:
    description = "datamaliciousorder - file 20161205_50c1813eb8475077704a2135da3f8eb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56b1c2525fa7480ffbeafba8312f74d3edfbd2d26705caabc2b0e36d812cb4d0"

  strings:
    $s1 = "function _DTm4(s) {var _Fx6 = new Date();_Fx6.setUTCFullYear(\"2003\");if (_Fx6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DTm4(s) {var _Fx6 = new Date();_Fx6.setUTCFullYear(\"2003\");if (_Fx6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VOq0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}