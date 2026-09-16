rule sig_20161206_351e6cf83784e25c302da5135bd5950d {
  meta:
    description = "datamaliciousorder - file 20161206_351e6cf83784e25c302da5135bd5950d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48f0a84914cfae667c136bc9038f0482f707b31babd7e8c0e7a4634471bc481b"

  strings:
    $s1 = "function _SPt7(s) {var _Bs2 = new Date();_Bs2.setUTCFullYear(\"2003\");if (_Bs2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SPt7(s) {var _Bs2 = new Date();_Bs2.setUTCFullYear(\"2003\");if (_Bs2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NKq9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}