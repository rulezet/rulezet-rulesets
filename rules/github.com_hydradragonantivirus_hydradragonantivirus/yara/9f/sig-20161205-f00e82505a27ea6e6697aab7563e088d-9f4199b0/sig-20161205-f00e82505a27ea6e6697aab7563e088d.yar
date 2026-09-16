rule sig_20161205_f00e82505a27ea6e6697aab7563e088d {
  meta:
    description = "datamaliciousorder - file 20161205_f00e82505a27ea6e6697aab7563e088d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c163553c1da52d44752337be3a3aa034dd9ab06cb3afde94716baa39aa02a2a"

  strings:
    $s1 = "function _BXb4(s) {var _Bv1 = new Date();_Bv1.setUTCFullYear(\"2003\");if (_Bv1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BXb4(s) {var _Bv1 = new Date();_Bv1.setUTCFullYear(\"2003\");if (_Bv1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _UYf7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}