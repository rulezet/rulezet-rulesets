rule sig_20161205_2bb4c3602036e52ece1047e89fd420ee {
  meta:
    description = "datamaliciousorder - file 20161205_2bb4c3602036e52ece1047e89fd420ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54dda7da01dc377e5ad5aab94c16af0ad6655636d7781082f42a541aab7fdc29"

  strings:
    $s1 = "function _Hx3(s) {var _SHk6 = new Date();_SHk6.setUTCFullYear(\"2003\");if (_SHk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hx3(s) {var _SHk6 = new Date();_SHk6.setUTCFullYear(\"2003\");if (_SHk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _AXc0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}