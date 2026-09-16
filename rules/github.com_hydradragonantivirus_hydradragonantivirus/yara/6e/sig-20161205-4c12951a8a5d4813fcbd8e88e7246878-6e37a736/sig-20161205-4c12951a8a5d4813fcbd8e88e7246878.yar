rule sig_20161205_4c12951a8a5d4813fcbd8e88e7246878 {
  meta:
    description = "datamaliciousorder - file 20161205_4c12951a8a5d4813fcbd8e88e7246878.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8aefddacddc3b850c6e6c58b207a2962c055763c679525d8a96483d367620fc9"

  strings:
    $s1 = "function _Uw5(s) {var _Vr6 = new Date();_Vr6.setUTCFullYear(\"2003\");if (_Vr6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uw5(s) {var _Vr6 = new Date();_Vr6.setUTCFullYear(\"2003\");if (_Vr6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sg0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}