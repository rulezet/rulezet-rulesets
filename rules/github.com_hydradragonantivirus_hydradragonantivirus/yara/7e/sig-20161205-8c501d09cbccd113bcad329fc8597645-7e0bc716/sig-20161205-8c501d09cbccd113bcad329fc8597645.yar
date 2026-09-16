rule sig_20161205_8c501d09cbccd113bcad329fc8597645 {
  meta:
    description = "datamaliciousorder - file 20161205_8c501d09cbccd113bcad329fc8597645.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "748a48a7b8e34a5cd82c46ef929a821854649a0902a40c5d2a1905ba70c26d40"

  strings:
    $s1 = "function _Nw3(s) {var _GSt0 = new Date();_GSt0.setUTCFullYear(\"2003\");if (_GSt0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nw3(s) {var _GSt0 = new Date();_GSt0.setUTCFullYear(\"2003\");if (_GSt0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Sr9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}