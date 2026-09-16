rule sig_20161205_28204f5209a883e73ccdc0545edc5308 {
  meta:
    description = "datamaliciousorder - file 20161205_28204f5209a883e73ccdc0545edc5308.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e25a4dcea2adf72d7cd5b4be01e2e30f720cb00c5d89e37e9431dff30e21dc7"

  strings:
    $s1 = "function _IYg5(s) {var _EMk5 = new Date();_EMk5.setUTCFullYear(\"2003\");if (_EMk5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IYg5(s) {var _EMk5 = new Date();_EMk5.setUTCFullYear(\"2003\");if (_EMk5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _XXq4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}