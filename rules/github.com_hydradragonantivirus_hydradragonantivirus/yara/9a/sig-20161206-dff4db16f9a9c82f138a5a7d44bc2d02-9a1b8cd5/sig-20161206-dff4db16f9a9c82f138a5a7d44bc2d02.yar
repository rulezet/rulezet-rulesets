rule sig_20161206_dff4db16f9a9c82f138a5a7d44bc2d02 {
  meta:
    description = "datamaliciousorder - file 20161206_dff4db16f9a9c82f138a5a7d44bc2d02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4f778427db03fa246a08d4a487d6efeb52bb325c7170fec42383208becff444"

  strings:
    $s1 = "function _YSw1(s) {var _TGq5 = new Date();_TGq5.setUTCFullYear(\"2003\");if (_TGq5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YSw1(s) {var _TGq5 = new Date();_TGq5.setUTCFullYear(\"2003\");if (_TGq5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _UXa1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}