rule sig_20161205_f6d739b2ab2247aff482d23cfe6a76d3 {
  meta:
    description = "datamaliciousorder - file 20161205_f6d739b2ab2247aff482d23cfe6a76d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4280251f28d3bd5ea7e7f08da302ee1f11f86daeac46d774f81a5a109b1fc0e0"

  strings:
    $s1 = "function _IKw3(s) {var _Ht4 = new Date();_Ht4.setUTCFullYear(\"2003\");if (_Ht4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IKw3(s) {var _Ht4 = new Date();_Ht4.setUTCFullYear(\"2003\");if (_Ht4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _JPh7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}