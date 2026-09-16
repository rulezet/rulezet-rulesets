rule sig_20161205_54f82501f85d1bd8ed4fab6829aee67c {
  meta:
    description = "datamaliciousorder - file 20161205_54f82501f85d1bd8ed4fab6829aee67c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5dc097f4105aeee2a5dd23179288a64539392ed0e37c4eae87c321624412553"

  strings:
    $s1 = "function _Gr0(s) {var _GIk6 = new Date();_GIk6.setUTCFullYear(\"2003\");if (_GIk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gr0(s) {var _GIk6 = new Date();_GIk6.setUTCFullYear(\"2003\");if (_GIk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _SJb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}