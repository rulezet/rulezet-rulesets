rule sig_20161205_2201bf5f9ce2f4ced943a264a2b2176b {
  meta:
    description = "datamaliciousorder - file 20161205_2201bf5f9ce2f4ced943a264a2b2176b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a11393be6861d74e2c969cee5fa051e5478643c9c32b2d7d49abe73c2dc55c92"

  strings:
    $s1 = "function _ZAm8(s) {var _TOm4 = new Date();_TOm4.setUTCFullYear(\"2003\");if (_TOm4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZAm8(s) {var _TOm4 = new Date();_TOm4.setUTCFullYear(\"2003\");if (_TOm4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZZu9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}