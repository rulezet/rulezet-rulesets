rule sig_20161205_4123ccd60cccfad7bcf46d895016fbd5 {
  meta:
    description = "datamaliciousorder - file 20161205_4123ccd60cccfad7bcf46d895016fbd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2450107f483c4ece9ae0c57a39b4cc928ff1c1bd03890e0f8fac9255520e23f"

  strings:
    $s1 = "function _PXn4(s) {var _GVt8 = new Date();_GVt8.setUTCFullYear(\"2003\");if (_GVt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PXn4(s) {var _GVt8 = new Date();_GVt8.setUTCFullYear(\"2003\");if (_GVt8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _YOs5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}