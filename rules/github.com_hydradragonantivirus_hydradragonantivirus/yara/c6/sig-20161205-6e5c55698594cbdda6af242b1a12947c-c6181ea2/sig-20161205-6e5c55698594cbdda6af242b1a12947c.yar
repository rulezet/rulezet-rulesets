rule sig_20161205_6e5c55698594cbdda6af242b1a12947c {
  meta:
    description = "datamaliciousorder - file 20161205_6e5c55698594cbdda6af242b1a12947c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2cc00133a68072b4dfecddf8ff120b8ce0402cf8d1b1fcd80aa91c8ba871ee"

  strings:
    $s1 = "function _Lj8(s) {var _EFu5 = new Date();_EFu5.setUTCFullYear(\"2003\");if (_EFu5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lj8(s) {var _EFu5 = new Date();_EFu5.setUTCFullYear(\"2003\");if (_EFu5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Oo2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}