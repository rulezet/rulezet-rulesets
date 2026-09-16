rule sig_20161205_d57945e0853905573e0c428a576e8432 {
  meta:
    description = "datamaliciousorder - file 20161205_d57945e0853905573e0c428a576e8432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88581e0603ebc3fe803005c483bd51b2518f1d7a5e229b98cd55858725b05abe"

  strings:
    $s1 = "function _Ys3(s) {var _HAv9 = new Date();_HAv9.setUTCFullYear(\"2003\");if (_HAv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ys3(s) {var _HAv9 = new Date();_HAv9.setUTCFullYear(\"2003\");if (_HAv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _PJq0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}