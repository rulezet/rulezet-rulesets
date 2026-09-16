rule sig_20161205_a0e854c334e95871d51bce0f837e64f7 {
  meta:
    description = "datamaliciousorder - file 20161205_a0e854c334e95871d51bce0f837e64f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fc316f29ccc528efbfc305cd7b282f9f82a691fb09d90216d74b3f4ff6fee33"

  strings:
    $s1 = "function _Gw1(s) {var _RCq8 = new Date();_RCq8.setUTCFullYear(\"2003\");if (_RCq8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gw1(s) {var _RCq8 = new Date();_RCq8.setUTCFullYear(\"2003\");if (_RCq8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _PYa4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}