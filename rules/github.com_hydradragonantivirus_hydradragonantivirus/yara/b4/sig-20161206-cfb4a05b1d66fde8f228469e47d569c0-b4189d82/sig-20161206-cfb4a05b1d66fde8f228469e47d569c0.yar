rule sig_20161206_cfb4a05b1d66fde8f228469e47d569c0 {
  meta:
    description = "datamaliciousorder - file 20161206_cfb4a05b1d66fde8f228469e47d569c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19d9d5755c6c1c8bb605ac8967414278851f60b394c15d8d50aebd43f644c4e1"

  strings:
    $s1 = "function _EZd6(s) {var _Uh7 = new Date();_Uh7.setUTCFullYear(\"2003\");if (_Uh7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _EZd6(s) {var _Uh7 = new Date();_Uh7.setUTCFullYear(\"2003\");if (_Uh7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _DHo3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}