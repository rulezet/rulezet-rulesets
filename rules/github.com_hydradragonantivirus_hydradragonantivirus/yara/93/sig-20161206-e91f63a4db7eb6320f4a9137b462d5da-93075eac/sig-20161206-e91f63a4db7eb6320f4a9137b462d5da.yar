rule sig_20161206_e91f63a4db7eb6320f4a9137b462d5da {
  meta:
    description = "datamaliciousorder - file 20161206_e91f63a4db7eb6320f4a9137b462d5da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69cff4da7e9c2502c492099984168368e7043b9e85f152414e66b65e51453b7c"

  strings:
    $s1 = "function _KRu7(s) {var _Js1 = new Date();_Js1.setUTCFullYear(\"2003\");if (_Js1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KRu7(s) {var _Js1 = new Date();_Js1.setUTCFullYear(\"2003\");if (_Js1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RLa7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}