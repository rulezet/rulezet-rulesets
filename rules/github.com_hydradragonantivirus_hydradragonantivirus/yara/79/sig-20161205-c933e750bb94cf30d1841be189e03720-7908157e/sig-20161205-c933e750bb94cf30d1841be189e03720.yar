rule sig_20161205_c933e750bb94cf30d1841be189e03720 {
  meta:
    description = "datamaliciousorder - file 20161205_c933e750bb94cf30d1841be189e03720.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55bc614b944228bd040a15220cc8c91f0035427081c2908289dbd2644cd0c535"

  strings:
    $s1 = "function _ORd3(s) {var _Fx6 = new Date();_Fx6.setUTCFullYear(\"2003\");if (_Fx6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ORd3(s) {var _Fx6 = new Date();_Fx6.setUTCFullYear(\"2003\");if (_Fx6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ik3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}