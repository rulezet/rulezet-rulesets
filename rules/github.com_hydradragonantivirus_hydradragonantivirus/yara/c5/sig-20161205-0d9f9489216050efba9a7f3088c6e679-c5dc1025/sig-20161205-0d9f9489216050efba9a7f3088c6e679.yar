rule sig_20161205_0d9f9489216050efba9a7f3088c6e679 {
  meta:
    description = "datamaliciousorder - file 20161205_0d9f9489216050efba9a7f3088c6e679.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ff828619977dc01ad504a7503500f8f99eaf6638ea168f37fab0f3486eb8403"

  strings:
    $s1 = "function _LCz7(s) {var _BYp0 = new Date();_BYp0.setUTCFullYear(\"2003\");if (_BYp0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LCz7(s) {var _BYp0 = new Date();_BYp0.setUTCFullYear(\"2003\");if (_BYp0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZYi8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}