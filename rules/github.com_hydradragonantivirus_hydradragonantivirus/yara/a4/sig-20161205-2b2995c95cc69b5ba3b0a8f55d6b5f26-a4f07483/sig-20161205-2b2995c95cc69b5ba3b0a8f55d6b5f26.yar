rule sig_20161205_2b2995c95cc69b5ba3b0a8f55d6b5f26 {
  meta:
    description = "datamaliciousorder - file 20161205_2b2995c95cc69b5ba3b0a8f55d6b5f26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "172f0bbb493c2eea70073d9faca5f0ede1ac50c9849c7955f0035bb7510be8e6"

  strings:
    $s1 = "function _Na5(s) {var _Oy3 = new Date();_Oy3.setUTCFullYear(\"2003\");if (_Oy3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Na5(s) {var _Oy3 = new Date();_Oy3.setUTCFullYear(\"2003\");if (_Oy3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Kr8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}