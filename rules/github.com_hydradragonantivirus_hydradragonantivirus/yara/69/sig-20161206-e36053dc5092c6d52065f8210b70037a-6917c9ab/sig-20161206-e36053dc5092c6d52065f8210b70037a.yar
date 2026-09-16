rule sig_20161206_e36053dc5092c6d52065f8210b70037a {
  meta:
    description = "datamaliciousorder - file 20161206_e36053dc5092c6d52065f8210b70037a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2d503f5829238da465ec4a4f394c34db0be10dac195d9fb5b9c09018f2251bb"

  strings:
    $s1 = "function _VHn5(s) {var _Mx0 = new Date();_Mx0.setUTCFullYear(\"2003\");if (_Mx0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VHn5(s) {var _Mx0 = new Date();_Mx0.setUTCFullYear(\"2003\");if (_Mx0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Hh1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}