rule sig_20161205_4573a0528498e172f5d6f09f2d69f898 {
  meta:
    description = "datamaliciousorder - file 20161205_4573a0528498e172f5d6f09f2d69f898.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "188708518c93c7f2d7212612ddf49219e95df627e4bc8d22f7f46d74ac90808e"

  strings:
    $s1 = "function _CNb9(s) {var _Dd5 = new Date();_Dd5.setUTCFullYear(\"2003\");if (_Dd5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _CNb9(s) {var _Dd5 = new Date();_Dd5.setUTCFullYear(\"2003\");if (_Dd5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Yu9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}