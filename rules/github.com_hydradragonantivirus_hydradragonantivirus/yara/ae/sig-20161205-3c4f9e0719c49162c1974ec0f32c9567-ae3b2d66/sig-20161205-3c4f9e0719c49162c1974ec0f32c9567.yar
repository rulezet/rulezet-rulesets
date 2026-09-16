rule sig_20161205_3c4f9e0719c49162c1974ec0f32c9567 {
  meta:
    description = "datamaliciousorder - file 20161205_3c4f9e0719c49162c1974ec0f32c9567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17977937fffe2ed159e26d3ae107403fa943bf284c342929b2a95c26a0c53be"

  strings:
    $s1 = "function _CDx6(s) {var _Xm9 = new Date();_Xm9.setUTCFullYear(\"2003\");if (_Xm9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _CDx6(s) {var _Xm9 = new Date();_Xm9.setUTCFullYear(\"2003\");if (_Xm9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Sx1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}