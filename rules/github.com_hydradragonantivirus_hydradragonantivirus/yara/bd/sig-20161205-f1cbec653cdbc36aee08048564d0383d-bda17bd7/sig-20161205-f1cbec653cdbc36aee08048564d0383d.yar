rule sig_20161205_f1cbec653cdbc36aee08048564d0383d {
  meta:
    description = "datamaliciousorder - file 20161205_f1cbec653cdbc36aee08048564d0383d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0bfa96db42b1dda7b27aca9632474dd53687acb5ebc93fcea4f4e4fc1338a4d"

  strings:
    $s1 = "function _YZr8(s) {var _JAi6 = new Date();_JAi6.setUTCFullYear(\"2003\");if (_JAi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _YZr8(s) {var _JAi6 = new Date();_JAi6.setUTCFullYear(\"2003\");if (_JAi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EBu0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}