rule sig_20161205_c1131d1f4c572a81fbda3f5052a81098 {
  meta:
    description = "datamaliciousorder - file 20161205_c1131d1f4c572a81fbda3f5052a81098.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b8dd23feee876e8e5dec6a26436817982f5ae994e959e2f36fa4dc1eda37917"

  strings:
    $s1 = "function _MDc8(s) {var _GXd3 = new Date();_GXd3.setUTCFullYear(\"2003\");if (_GXd3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MDc8(s) {var _GXd3 = new Date();_GXd3.setUTCFullYear(\"2003\");if (_GXd3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Lk4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}