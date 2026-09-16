rule sig_20161205_18d220b4619d978bff36ecc9bdaa804a {
  meta:
    description = "datamaliciousorder - file 20161205_18d220b4619d978bff36ecc9bdaa804a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c469fe76e9e7699fe31c2396c46d62ae30ee430155d06de8375c106df2d0068e"

  strings:
    $s1 = "function _PRu4(s) {var _HWf0 = new Date();_HWf0.setUTCFullYear(\"2003\");if (_HWf0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PRu4(s) {var _HWf0 = new Date();_HWf0.setUTCFullYear(\"2003\");if (_HWf0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _OSp9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}