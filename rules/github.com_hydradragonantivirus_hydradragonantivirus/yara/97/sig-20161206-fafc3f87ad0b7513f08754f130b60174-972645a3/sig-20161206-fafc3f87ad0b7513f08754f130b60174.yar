rule sig_20161206_fafc3f87ad0b7513f08754f130b60174 {
  meta:
    description = "datamaliciousorder - file 20161206_fafc3f87ad0b7513f08754f130b60174.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d60e3c9a781985d0eb6020631e66b154bfeb90e0055099acd29025004071aa01"

  strings:
    $s1 = "function _DUs8(s) {var _EAw2 = new Date();_EAw2.setUTCFullYear(\"2003\");if (_EAw2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DUs8(s) {var _EAw2 = new Date();_EAw2.setUTCFullYear(\"2003\");if (_EAw2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ew7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}