rule sig_20161205_900104f5bd9a02de3e7ab27e525b258c {
  meta:
    description = "datamaliciousorder - file 20161205_900104f5bd9a02de3e7ab27e525b258c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a5c15efe4f486d252b9125ac48b3c3aca25c7efa05bfadf5330fd4b7746fd4"

  strings:
    $s1 = "function _KEq1(s) {var _ZTv3 = new Date();_ZTv3.setUTCFullYear(\"2003\");if (_ZTv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KEq1(s) {var _ZTv3 = new Date();_ZTv3.setUTCFullYear(\"2003\");if (_ZTv3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ro4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}