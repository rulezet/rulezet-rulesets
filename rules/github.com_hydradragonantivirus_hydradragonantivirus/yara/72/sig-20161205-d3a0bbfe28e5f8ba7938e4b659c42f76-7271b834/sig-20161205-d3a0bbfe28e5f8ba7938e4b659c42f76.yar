rule sig_20161205_d3a0bbfe28e5f8ba7938e4b659c42f76 {
  meta:
    description = "datamaliciousorder - file 20161205_d3a0bbfe28e5f8ba7938e4b659c42f76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f542a67b163178befeec7ff57e667e779f4e0a6b7d355b16117eaac4efaefa1b"

  strings:
    $s1 = "function _Lr7(s) {var _Yt7 = new Date();_Yt7.setUTCFullYear(\"2003\");if (_Yt7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Lr7(s) {var _Yt7 = new Date();_Yt7.setUTCFullYear(\"2003\");if (_Yt7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PUi4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}