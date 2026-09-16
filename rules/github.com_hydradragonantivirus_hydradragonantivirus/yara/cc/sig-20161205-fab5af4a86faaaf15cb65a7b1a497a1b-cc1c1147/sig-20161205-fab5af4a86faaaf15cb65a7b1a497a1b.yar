rule sig_20161205_fab5af4a86faaaf15cb65a7b1a497a1b {
  meta:
    description = "datamaliciousorder - file 20161205_fab5af4a86faaaf15cb65a7b1a497a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f5711c2c971e37a3957cbd961fcd1b33062557a74f422cb2d883a6b3eafc78e"

  strings:
    $s1 = "function _YLy9(s) {var _Pp5 = new Date();_Pp5.setUTCFullYear(\"2003\");if (_Pp5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YLy9(s) {var _Pp5 = new Date();_Pp5.setUTCFullYear(\"2003\");if (_Pp5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Nr7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}