rule sig_20161206_b1db434a425008518a10f99c8a19d706 {
  meta:
    description = "datamaliciousorder - file 20161206_b1db434a425008518a10f99c8a19d706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee31bc7be9b61b04fa8eaf55476ce3cfd20306991cf0a9693b5d8f4f2e9c802"

  strings:
    $s1 = "function _VFr9(s) {var _Ja8 = new Date();_Ja8.setUTCFullYear(\"2003\");if (_Ja8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VFr9(s) {var _Ja8 = new Date();_Ja8.setUTCFullYear(\"2003\");if (_Ja8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VEq4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}