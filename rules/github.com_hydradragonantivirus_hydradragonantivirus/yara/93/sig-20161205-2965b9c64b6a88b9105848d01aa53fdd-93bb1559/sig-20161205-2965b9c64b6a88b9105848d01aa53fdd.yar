rule sig_20161205_2965b9c64b6a88b9105848d01aa53fdd {
  meta:
    description = "datamaliciousorder - file 20161205_2965b9c64b6a88b9105848d01aa53fdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caed235a6de8932e07bf8f9c0c47b54bafc32c3ec2519c6d13af2e1379ca845"

  strings:
    $s1 = "function _YBp4(s) {var _ESs7 = new Date();_ESs7.setUTCFullYear(\"2003\");if (_ESs7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YBp4(s) {var _ESs7 = new Date();_ESs7.setUTCFullYear(\"2003\");if (_ESs7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Yl0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}