rule sig_20161206_8ffd611232fc73523c0687e0be9fc35d {
  meta:
    description = "datamaliciousorder - file 20161206_8ffd611232fc73523c0687e0be9fc35d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f88b040b54a779e15a15eebf2e70dbeb04b64046306b93f3b879de1e2b57a16"

  strings:
    $s1 = "function _HZe5(s) {var _Wv0 = new Date();_Wv0.setUTCFullYear(\"2003\");if (_Wv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HZe5(s) {var _Wv0 = new Date();_Wv0.setUTCFullYear(\"2003\");if (_Wv0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vt6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}