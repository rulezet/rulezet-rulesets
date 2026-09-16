rule sig_20161205_582b096d984f4d5c0f4228dbcf0da8a9 {
  meta:
    description = "datamaliciousorder - file 20161205_582b096d984f4d5c0f4228dbcf0da8a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec089316be11d755f5230c26534313daa93c1f2f0c1b2ee6a26e96510e30d5ac"

  strings:
    $s1 = "function _KXw1(s) {var _Yd2 = new Date();_Yd2.setUTCFullYear(\"2003\");if (_Yd2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KXw1(s) {var _Yd2 = new Date();_Yd2.setUTCFullYear(\"2003\");if (_Yd2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VTz3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}