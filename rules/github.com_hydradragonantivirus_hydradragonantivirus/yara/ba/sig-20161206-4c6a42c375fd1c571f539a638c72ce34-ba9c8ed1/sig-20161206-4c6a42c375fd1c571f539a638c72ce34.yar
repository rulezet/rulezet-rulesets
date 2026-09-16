rule sig_20161206_4c6a42c375fd1c571f539a638c72ce34 {
  meta:
    description = "datamaliciousorder - file 20161206_4c6a42c375fd1c571f539a638c72ce34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "184b620a33f0937352713b631907f72432d0f7ed252fa70b3ebd96ad0bf3af39"

  strings:
    $s1 = "function _DZu2(s) {var _Eo3 = new Date();_Eo3.setUTCFullYear(\"2003\");if (_Eo3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DZu2(s) {var _Eo3 = new Date();_Eo3.setUTCFullYear(\"2003\");if (_Eo3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Yw0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}