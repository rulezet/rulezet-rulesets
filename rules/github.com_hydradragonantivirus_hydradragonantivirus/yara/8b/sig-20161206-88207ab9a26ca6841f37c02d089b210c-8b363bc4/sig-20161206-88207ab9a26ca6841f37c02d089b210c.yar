rule sig_20161206_88207ab9a26ca6841f37c02d089b210c {
  meta:
    description = "datamaliciousorder - file 20161206_88207ab9a26ca6841f37c02d089b210c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4ad606e1b0f97a91168e0867aae89c07071843ced098bda4ce56385759aec2b"

  strings:
    $s1 = "function _Km6(s) {var _Eq3 = new Date();_Eq3.setUTCFullYear(\"2003\");if (_Eq3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Km6(s) {var _Eq3 = new Date();_Eq3.setUTCFullYear(\"2003\");if (_Eq3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _NBv2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}