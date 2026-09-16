rule sig_20161205_e20e90074e061b0db9fa625d907759d6 {
  meta:
    description = "datamaliciousorder - file 20161205_e20e90074e061b0db9fa625d907759d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db95d540af2d6a9f458f2fcf6858d02fc6ea2be6a29a018d304c7ff82dfd2af"

  strings:
    $s1 = "function _Xc1(s) {var _DGm3 = new Date();_DGm3.setUTCFullYear(\"2003\");if (_DGm3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Xc1(s) {var _DGm3 = new Date();_DGm3.setUTCFullYear(\"2003\");if (_DGm3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _QIg5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}