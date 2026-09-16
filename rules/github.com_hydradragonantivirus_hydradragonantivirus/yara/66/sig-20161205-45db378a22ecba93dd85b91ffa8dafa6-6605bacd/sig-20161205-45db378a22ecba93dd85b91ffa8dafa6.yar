rule sig_20161205_45db378a22ecba93dd85b91ffa8dafa6 {
  meta:
    description = "datamaliciousorder - file 20161205_45db378a22ecba93dd85b91ffa8dafa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ca0a9ffc3f4ebacf1b042ec7944443aa5f64dd8778dd9418c94623e0e67c94f"

  strings:
    $s1 = "function _EUa3(s) {var _YWs0 = new Date();_YWs0.setUTCFullYear(\"2003\");if (_YWs0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _EUa3(s) {var _YWs0 = new Date();_YWs0.setUTCFullYear(\"2003\");if (_YWs0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _GRq3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}