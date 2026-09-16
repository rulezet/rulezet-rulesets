rule sig_20161205_39786f0f56b17feb7c54de581ee1d515 {
  meta:
    description = "datamaliciousorder - file 20161205_39786f0f56b17feb7c54de581ee1d515.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bcc4d5e8691e0b2b869abce9d076d9f1b28543b2846c9bed221b7dd5cff7e82"

  strings:
    $s1 = "function _LKx5(s) {var _Ff3 = new Date();_Ff3.setUTCFullYear(\"2003\");if (_Ff3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _LKx5(s) {var _Ff3 = new Date();_Ff3.setUTCFullYear(\"2003\");if (_Ff3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TGr3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}