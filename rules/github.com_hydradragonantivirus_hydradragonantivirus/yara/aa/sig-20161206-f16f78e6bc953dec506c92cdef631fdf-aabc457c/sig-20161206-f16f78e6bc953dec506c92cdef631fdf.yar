rule sig_20161206_f16f78e6bc953dec506c92cdef631fdf {
  meta:
    description = "datamaliciousorder - file 20161206_f16f78e6bc953dec506c92cdef631fdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd51ea196b2faafe7efe0284aa075fa5ecc698a31af038e757db013f4a314d9b"

  strings:
    $s1 = "function _IAs0(s) {var _Sb9 = new Date();_Sb9.setUTCFullYear(\"2003\");if (_Sb9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IAs0(s) {var _Sb9 = new Date();_Sb9.setUTCFullYear(\"2003\");if (_Sb9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Nd2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}