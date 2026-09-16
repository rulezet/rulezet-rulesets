rule sig_20161205_da95f2d16d2e3c163f2286fa1062d9bd {
  meta:
    description = "datamaliciousorder - file 20161205_da95f2d16d2e3c163f2286fa1062d9bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8679f95827fab8a2e828daf7c7bab9956101a78cd91728e917cf73327662e1be"

  strings:
    $s1 = "function _FMx5(s) {var _RAa3 = new Date();_RAa3.setUTCFullYear(\"2003\");if (_RAa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FMx5(s) {var _RAa3 = new Date();_RAa3.setUTCFullYear(\"2003\");if (_RAa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _QLt7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}