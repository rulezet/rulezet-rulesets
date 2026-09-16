rule sig_20161205_645a2f8f6d49c3c82c84b67472fb4103 {
  meta:
    description = "datamaliciousorder - file 20161205_645a2f8f6d49c3c82c84b67472fb4103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ccb7c98bd7794d0caca50aa7262b65c22a2c26b98e9c5fee675024f2891f0b2"

  strings:
    $s1 = "function _Px0(s) {var _Hu1 = new Date();_Hu1.setUTCFullYear(\"2003\");if (_Hu1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Px0(s) {var _Hu1 = new Date();_Hu1.setUTCFullYear(\"2003\");if (_Hu1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XVg0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}