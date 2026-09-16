rule sig_20161205_7b9438f53da3ddc30ae8f5bba8a4cc06 {
  meta:
    description = "datamaliciousorder - file 20161205_7b9438f53da3ddc30ae8f5bba8a4cc06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b00f19945dfa4c81f3b382585cfe0602f16aaa45391b7c8547db4a884ecde6d"

  strings:
    $s1 = "function _VRh7(s) {var _Sx4 = new Date();_Sx4.setUTCFullYear(\"2003\");if (_Sx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _VRh7(s) {var _Sx4 = new Date();_Sx4.setUTCFullYear(\"2003\");if (_Sx4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Kk1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}