rule sig_20161205_97a4babf31bdcdfc415ba4904a1b11af {
  meta:
    description = "datamaliciousorder - file 20161205_97a4babf31bdcdfc415ba4904a1b11af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abcbad9e55b9693249bb270f9a8092aac7f19f83242143e64e088aaf29bb7a0c"

  strings:
    $s1 = "function _JAq2(s) {var _CCe3 = new Date();_CCe3.setUTCFullYear(\"2003\");if (_CCe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JAq2(s) {var _CCe3 = new Date();_CCe3.setUTCFullYear(\"2003\");if (_CCe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Mi6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}