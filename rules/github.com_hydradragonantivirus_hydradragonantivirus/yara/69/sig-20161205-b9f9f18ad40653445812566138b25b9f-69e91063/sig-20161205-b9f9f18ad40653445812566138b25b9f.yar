rule sig_20161205_b9f9f18ad40653445812566138b25b9f {
  meta:
    description = "datamaliciousorder - file 20161205_b9f9f18ad40653445812566138b25b9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef9e3245f9a92af8431ed451ab0e592bae8a154540b91d8774413f2e9dfde3f9"

  strings:
    $s1 = "function _IVf1(s) {var _YBt1 = new Date();_YBt1.setUTCFullYear(\"2003\");if (_YBt1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IVf1(s) {var _YBt1 = new Date();_YBt1.setUTCFullYear(\"2003\");if (_YBt1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _AHb2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}