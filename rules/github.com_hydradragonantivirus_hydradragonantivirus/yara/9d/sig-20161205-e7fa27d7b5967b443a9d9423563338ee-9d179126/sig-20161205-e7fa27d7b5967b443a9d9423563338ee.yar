rule sig_20161205_e7fa27d7b5967b443a9d9423563338ee {
  meta:
    description = "datamaliciousorder - file 20161205_e7fa27d7b5967b443a9d9423563338ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5de8decee8d4acd33690c831f4ed9ae27329feed41be705a92f2974049a05d5"

  strings:
    $s1 = "function _Jr5(s) {var _IFh6 = new Date();_IFh6.setUTCFullYear(\"2003\");if (_IFh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Jr5(s) {var _IFh6 = new Date();_IFh6.setUTCFullYear(\"2003\");if (_IFh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _CZr4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}