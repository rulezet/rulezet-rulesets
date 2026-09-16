rule sig_20161205_08c2a754fdc21de89eed0516491e7304 {
  meta:
    description = "datamaliciousorder - file 20161205_08c2a754fdc21de89eed0516491e7304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14b2257d0f8b003d9c8b42e33e93aab47052f2bf6f5e35c25cfa773ec3f9c12"

  strings:
    $s1 = "function _Rh5(s) {var _MJq2 = new Date();_MJq2.setUTCFullYear(\"2003\");if (_MJq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rh5(s) {var _MJq2 = new Date();_MJq2.setUTCFullYear(\"2003\");if (_MJq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DQo1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}