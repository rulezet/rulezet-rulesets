rule sig_20161205_e050a3a82b8ad1b6eb5361f8ec3bd8ac {
  meta:
    description = "datamaliciousorder - file 20161205_e050a3a82b8ad1b6eb5361f8ec3bd8ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34326e99ab3d7ab6291ab48d7ba92f02a7874c90e70fc615cffcb724c668158b"

  strings:
    $s1 = "function _MXy0(s) {var _Ee7 = new Date();_Ee7.setUTCFullYear(\"2003\");if (_Ee7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MXy0(s) {var _Ee7 = new Date();_Ee7.setUTCFullYear(\"2003\");if (_Ee7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _KNw0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}