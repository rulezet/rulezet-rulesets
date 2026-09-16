rule sig_20161205_a3d06dfdf1a656863fa41ae63c21cc26 {
  meta:
    description = "datamaliciousorder - file 20161205_a3d06dfdf1a656863fa41ae63c21cc26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1bb76f6481b11954ac40aa3b6c1f924dc7a2007b699d65f8761e01755ac6a7b"

  strings:
    $s1 = "function _Et0(s) {var _Md3 = new Date();_Md3.setUTCFullYear(\"2003\");if (_Md3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Et0(s) {var _Md3 = new Date();_Md3.setUTCFullYear(\"2003\");if (_Md3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Cd9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}