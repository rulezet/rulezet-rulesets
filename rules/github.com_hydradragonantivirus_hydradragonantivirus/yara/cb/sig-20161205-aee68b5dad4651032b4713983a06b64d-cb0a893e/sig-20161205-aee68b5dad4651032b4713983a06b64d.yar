rule sig_20161205_aee68b5dad4651032b4713983a06b64d {
  meta:
    description = "datamaliciousorder - file 20161205_aee68b5dad4651032b4713983a06b64d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36260cf91b5f72c6d402056e6d64722a554c04e9591cf6487b79d53507b4fb20"

  strings:
    $s1 = "function _Dq3(s) {var _Oz5 = new Date();_Oz5.setUTCFullYear(\"2003\");if (_Oz5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dq3(s) {var _Oz5 = new Date();_Oz5.setUTCFullYear(\"2003\");if (_Oz5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Hy4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}