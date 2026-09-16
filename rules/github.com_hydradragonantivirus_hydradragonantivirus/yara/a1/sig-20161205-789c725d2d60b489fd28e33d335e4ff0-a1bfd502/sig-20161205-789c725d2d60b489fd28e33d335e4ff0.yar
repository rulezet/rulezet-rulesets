rule sig_20161205_789c725d2d60b489fd28e33d335e4ff0 {
  meta:
    description = "datamaliciousorder - file 20161205_789c725d2d60b489fd28e33d335e4ff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "919ca93a2597d7a644e6a5de01de9b2892b97d9aaaa91ac9c62d68d70b115873"

  strings:
    $s1 = "function _Zi4(s) {var _NDi4 = new Date();_NDi4.setUTCFullYear(\"2003\");if (_NDi4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zi4(s) {var _NDi4 = new Date();_NDi4.setUTCFullYear(\"2003\");if (_NDi4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _He3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}