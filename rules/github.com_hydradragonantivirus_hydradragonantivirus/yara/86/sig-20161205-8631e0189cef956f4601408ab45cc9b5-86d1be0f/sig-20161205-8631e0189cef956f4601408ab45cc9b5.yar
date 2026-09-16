rule sig_20161205_8631e0189cef956f4601408ab45cc9b5 {
  meta:
    description = "datamaliciousorder - file 20161205_8631e0189cef956f4601408ab45cc9b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93bca10f429589de9af1270d74817100e7d2f6642dc6d01169a18419a5ab323f"

  strings:
    $s1 = "function _UBk0(s) {var _HBz3 = new Date();_HBz3.setUTCFullYear(\"2003\");if (_HBz3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _UBk0(s) {var _HBz3 = new Date();_HBz3.setUTCFullYear(\"2003\");if (_HBz3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ABq1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}