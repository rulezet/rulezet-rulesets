rule sig_20161205_778d61a4fdafdf3ad4886a8141ea562d {
  meta:
    description = "datamaliciousorder - file 20161205_778d61a4fdafdf3ad4886a8141ea562d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87103c875b15bdd9c0e7148ac50151e47b8297203f7e04ba98ddd2d4e59afec1"

  strings:
    $s1 = "function _FPd4(s) {var _Kk4 = new Date();_Kk4.setUTCFullYear(\"2003\");if (_Kk4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FPd4(s) {var _Kk4 = new Date();_Kk4.setUTCFullYear(\"2003\");if (_Kk4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _AMw0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}