rule sig_20161205_8753250d88bee1b0c891201d7b17aa2a {
  meta:
    description = "datamaliciousorder - file 20161205_8753250d88bee1b0c891201d7b17aa2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5b1c3af11e765b7b387b58ea5816dda25e6804bc3cb01180fa499922b76c9d1"

  strings:
    $s1 = "function _Al9(s) {var _Kx3 = new Date();_Kx3.setUTCFullYear(\"2003\");if (_Kx3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Al9(s) {var _Kx3 = new Date();_Kx3.setUTCFullYear(\"2003\");if (_Kx3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qo8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}