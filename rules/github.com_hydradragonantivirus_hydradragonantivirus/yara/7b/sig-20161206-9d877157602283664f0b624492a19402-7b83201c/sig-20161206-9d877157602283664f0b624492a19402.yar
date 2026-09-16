rule sig_20161206_9d877157602283664f0b624492a19402 {
  meta:
    description = "datamaliciousorder - file 20161206_9d877157602283664f0b624492a19402.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de99b92838c5b3278ba0a49eccb6ff235ba74e5840080907def82dcfd3e080bf"

  strings:
    $s1 = "function _EBr8(s) {var _Bl3 = new Date();_Bl3.setUTCFullYear(\"2003\");if (_Bl3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _EBr8(s) {var _Bl3 = new Date();_Bl3.setUTCFullYear(\"2003\");if (_Bl3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NQf5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}