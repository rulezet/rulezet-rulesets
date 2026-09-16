rule sig_20161205_57c1fe98884a6986a596582ff6693557 {
  meta:
    description = "datamaliciousorder - file 20161205_57c1fe98884a6986a596582ff6693557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5696ad169c8e5be5b6b775d19c22aef2cf12554df8511d3273fe9b900569fe1"

  strings:
    $s1 = "function _IGz2(s) {var _DKo1 = new Date();_DKo1.setUTCFullYear(\"2003\");if (_DKo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IGz2(s) {var _DKo1 = new Date();_DKo1.setUTCFullYear(\"2003\");if (_DKo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Lk3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}