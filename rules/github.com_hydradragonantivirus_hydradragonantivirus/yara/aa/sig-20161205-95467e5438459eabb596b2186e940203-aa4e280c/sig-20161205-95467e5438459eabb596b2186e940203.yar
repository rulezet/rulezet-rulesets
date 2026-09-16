rule sig_20161205_95467e5438459eabb596b2186e940203 {
  meta:
    description = "datamaliciousorder - file 20161205_95467e5438459eabb596b2186e940203.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d3d18a97789fa9e3760625d71647c5a470c795d2806e3d20da35c487dd14f8f"

  strings:
    $s1 = "function _Dj3(s) {var _Ck3 = new Date();_Ck3.setUTCFullYear(\"2003\");if (_Ck3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dj3(s) {var _Ck3 = new Date();_Ck3.setUTCFullYear(\"2003\");if (_Ck3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ALp7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}