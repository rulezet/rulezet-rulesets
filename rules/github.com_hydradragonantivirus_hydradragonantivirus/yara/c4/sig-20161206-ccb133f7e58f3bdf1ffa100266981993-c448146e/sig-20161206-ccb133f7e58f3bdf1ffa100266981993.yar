rule sig_20161206_ccb133f7e58f3bdf1ffa100266981993 {
  meta:
    description = "datamaliciousorder - file 20161206_ccb133f7e58f3bdf1ffa100266981993.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c032219aa3bbf20923c1606b2332cc95aa12c919d0db2c6b26b725f1658746ad"

  strings:
    $s1 = "function _My8(s) {var _LBs1 = new Date();_LBs1.setUTCFullYear(\"2003\");if (_LBs1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _My8(s) {var _LBs1 = new Date();_LBs1.setUTCFullYear(\"2003\");if (_LBs1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _MWl2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}