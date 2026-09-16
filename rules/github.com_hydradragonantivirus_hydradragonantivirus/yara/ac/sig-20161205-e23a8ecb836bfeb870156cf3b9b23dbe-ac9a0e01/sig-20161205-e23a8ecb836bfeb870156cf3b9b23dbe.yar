rule sig_20161205_e23a8ecb836bfeb870156cf3b9b23dbe {
  meta:
    description = "datamaliciousorder - file 20161205_e23a8ecb836bfeb870156cf3b9b23dbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc713aea5ac6fe991301dddc92f7091207de27d6c2568786fcb4f94e36e65dcb"

  strings:
    $s1 = "function _UEm3(s) {var _Ta4 = new Date();_Ta4.setUTCFullYear(\"2003\");if (_Ta4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UEm3(s) {var _Ta4 = new Date();_Ta4.setUTCFullYear(\"2003\");if (_Ta4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Gi4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}