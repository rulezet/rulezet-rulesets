rule sig_20161205_30e4c0e354e19d9fcf6771a87224c1f4 {
  meta:
    description = "datamaliciousorder - file 20161205_30e4c0e354e19d9fcf6771a87224c1f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "241d5e5b246c1b6811c024ca7853516afcad47d2477994780ed058fbd5755c87"

  strings:
    $s1 = "function _XAm2(s) {var _YUe8 = new Date();_YUe8.setUTCFullYear(\"2003\");if (_YUe8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XAm2(s) {var _YUe8 = new Date();_YUe8.setUTCFullYear(\"2003\");if (_YUe8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _HWh5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}