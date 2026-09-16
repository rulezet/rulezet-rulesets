rule sig_20161205_deb91d6d7ccbeac45fb4600de6a566a1 {
  meta:
    description = "datamaliciousorder - file 20161205_deb91d6d7ccbeac45fb4600de6a566a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e96d2c620fc0069d55cf5941bae1fe1e1ca7eccedab167e7b363ce45be4132"

  strings:
    $s1 = "function _Di5(s) {var _WXu8 = new Date();_WXu8.setUTCFullYear(\"2003\");if (_WXu8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Di5(s) {var _WXu8 = new Date();_WXu8.setUTCFullYear(\"2003\");if (_WXu8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Wa8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}