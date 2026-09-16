rule sig_20161205_0b95df46143b14d38fd30e75f7d1edd6 {
  meta:
    description = "datamaliciousorder - file 20161205_0b95df46143b14d38fd30e75f7d1edd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff849b99fe4c8ceca917f9a812d5d65f5830079b60d720adf55102bc865c6898"

  strings:
    $s1 = "function _DOi7(s) {var _VWg7 = new Date();_VWg7.setUTCFullYear(\"2003\");if (_VWg7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DOi7(s) {var _VWg7 = new Date();_VWg7.setUTCFullYear(\"2003\");if (_VWg7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WZm7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}