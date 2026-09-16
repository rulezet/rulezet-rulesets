rule sig_20161205_7a0f4ca184dab16e8e2a5eb5294827ee {
  meta:
    description = "datamaliciousorder - file 20161205_7a0f4ca184dab16e8e2a5eb5294827ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dba3724b4a79a50f9e75e4300f3812d8ef7f57cf9f6516adb0dd591f676381d"

  strings:
    $s1 = "function _Vb5(s) {var _Us6 = new Date();_Us6.setUTCFullYear(\"2003\");if (_Us6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Vb5(s) {var _Us6 = new Date();_Us6.setUTCFullYear(\"2003\");if (_Us6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _LWw2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}