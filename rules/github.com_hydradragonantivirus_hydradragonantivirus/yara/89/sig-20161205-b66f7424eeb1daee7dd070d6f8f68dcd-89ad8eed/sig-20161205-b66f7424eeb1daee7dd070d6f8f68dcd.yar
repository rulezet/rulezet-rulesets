rule sig_20161205_b66f7424eeb1daee7dd070d6f8f68dcd {
  meta:
    description = "datamaliciousorder - file 20161205_b66f7424eeb1daee7dd070d6f8f68dcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ec96d94425c09a432d7aa18bebcb438d3237cd42e8f797ed97ad4cb45f5405f"

  strings:
    $s1 = "function _Vh8(s) {var _NRg5 = new Date();_NRg5.setUTCFullYear(\"2003\");if (_NRg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Vh8(s) {var _NRg5 = new Date();_NRg5.setUTCFullYear(\"2003\");if (_NRg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Kl6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}