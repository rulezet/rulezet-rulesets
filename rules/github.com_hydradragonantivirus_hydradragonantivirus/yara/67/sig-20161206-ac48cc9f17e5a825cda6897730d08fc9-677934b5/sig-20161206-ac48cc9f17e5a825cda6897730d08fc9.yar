rule sig_20161206_ac48cc9f17e5a825cda6897730d08fc9 {
  meta:
    description = "datamaliciousorder - file 20161206_ac48cc9f17e5a825cda6897730d08fc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fda97438f3a43257d5f60a186abff1da204cb8be836721b4e937668c55d168f"

  strings:
    $s1 = "function _Xl1(s) {var _At2 = new Date();_At2.setUTCFullYear(\"2003\");if (_At2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xl1(s) {var _At2 = new Date();_At2.setUTCFullYear(\"2003\");if (_At2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ys3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}