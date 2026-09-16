rule sig_20161205_51229eb1d213b6fde830b833e8365e68 {
  meta:
    description = "datamaliciousorder - file 20161205_51229eb1d213b6fde830b833e8365e68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ffab99cbf610d93131d45bf8fb29ffa3d5ad957729818076c014fdd772830e7"

  strings:
    $s1 = "function _Gz0(s) {var _VVs6 = new Date();_VVs6.setUTCFullYear(\"2003\");if (_VVs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gz0(s) {var _VVs6 = new Date();_VVs6.setUTCFullYear(\"2003\");if (_VVs6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _So5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}