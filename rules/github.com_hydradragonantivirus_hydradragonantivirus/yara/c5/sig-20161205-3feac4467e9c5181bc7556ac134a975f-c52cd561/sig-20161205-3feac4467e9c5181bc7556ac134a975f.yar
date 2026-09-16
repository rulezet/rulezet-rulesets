rule sig_20161205_3feac4467e9c5181bc7556ac134a975f {
  meta:
    description = "datamaliciousorder - file 20161205_3feac4467e9c5181bc7556ac134a975f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5367da1eccd3c88339e18e4b86534c0d0afca20912a3d5f353fcf7ff58a5e95"

  strings:
    $s1 = "function _Bw3(s) {var _KOy4 = new Date();_KOy4.setUTCFullYear(\"2003\");if (_KOy4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Bw3(s) {var _KOy4 = new Date();_KOy4.setUTCFullYear(\"2003\");if (_KOy4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _DEj2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}