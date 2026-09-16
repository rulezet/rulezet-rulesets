rule sig_20161205_d66187e72fff78a6a9fedc69405eed49 {
  meta:
    description = "datamaliciousorder - file 20161205_d66187e72fff78a6a9fedc69405eed49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a438c8ed6fbbed7ac83b1dab6036ac46072a5af3358dd748a6b772c5ad5b1a90"

  strings:
    $s1 = "function _CBk6(s) {var _YJv9 = new Date();_YJv9.setUTCFullYear(\"2003\");if (_YJv9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _CBk6(s) {var _YJv9 = new Date();_YJv9.setUTCFullYear(\"2003\");if (_YJv9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ui1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}