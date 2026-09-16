rule sig_20161205_7ef74c74fa5287d6e3c31204143fc944 {
  meta:
    description = "datamaliciousorder - file 20161205_7ef74c74fa5287d6e3c31204143fc944.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "631dba8e2af50b7ec13c9cb2e0e07b32bacf5c946da68e3852a2623102342482"

  strings:
    $s1 = "function _Va3(s) {var _IGu7 = new Date();_IGu7.setUTCFullYear(\"2003\");if (_IGu7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Va3(s) {var _IGu7 = new Date();_IGu7.setUTCFullYear(\"2003\");if (_IGu7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Lv1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}