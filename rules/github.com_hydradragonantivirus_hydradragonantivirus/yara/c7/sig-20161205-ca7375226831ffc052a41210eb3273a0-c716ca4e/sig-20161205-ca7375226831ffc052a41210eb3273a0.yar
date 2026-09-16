rule sig_20161205_ca7375226831ffc052a41210eb3273a0 {
  meta:
    description = "datamaliciousorder - file 20161205_ca7375226831ffc052a41210eb3273a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5364b9983a2cd50e1555f3a0efaa03d2fd2b72535c649ae9ec07e1b83deb64ab"

  strings:
    $s1 = "function _JCg8(s) {var _MUe4 = new Date();_MUe4.setUTCFullYear(\"2003\");if (_MUe4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JCg8(s) {var _MUe4 = new Date();_MUe4.setUTCFullYear(\"2003\");if (_MUe4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Li1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}