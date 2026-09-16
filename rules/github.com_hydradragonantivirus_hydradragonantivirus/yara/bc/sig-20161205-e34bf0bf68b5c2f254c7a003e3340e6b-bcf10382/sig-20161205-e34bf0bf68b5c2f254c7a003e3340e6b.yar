rule sig_20161205_e34bf0bf68b5c2f254c7a003e3340e6b {
  meta:
    description = "datamaliciousorder - file 20161205_e34bf0bf68b5c2f254c7a003e3340e6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d21be8552d2003602148a6eb6fb8c87f6cf7f2d27e799e4a75f90da0fae61a95"

  strings:
    $s1 = "function _Ga9(s) {var _RYg3 = new Date();_RYg3.setUTCFullYear(\"2003\");if (_RYg3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ga9(s) {var _RYg3 = new Date();_RYg3.setUTCFullYear(\"2003\");if (_RYg3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Dv0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}