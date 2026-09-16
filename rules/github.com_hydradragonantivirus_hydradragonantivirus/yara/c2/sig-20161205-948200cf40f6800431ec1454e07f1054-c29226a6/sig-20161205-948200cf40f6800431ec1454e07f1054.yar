rule sig_20161205_948200cf40f6800431ec1454e07f1054 {
  meta:
    description = "datamaliciousorder - file 20161205_948200cf40f6800431ec1454e07f1054.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94a2bedbf4519df39bf33cfeb196b4b9e95a00a4981083cb892d7d27871f376b"

  strings:
    $s1 = "function _Ap5(s) {var _Il2 = new Date();_Il2.setUTCFullYear(\"2003\");if (_Il2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ap5(s) {var _Il2 = new Date();_Il2.setUTCFullYear(\"2003\");if (_Il2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Dr3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}