rule sig_20161205_6d10b817f6dd8b69c88448264e58ed5e {
  meta:
    description = "datamaliciousorder - file 20161205_6d10b817f6dd8b69c88448264e58ed5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8397e12e39e30f5015e3bd41670ac9d95718e53c4a3def07ee820b199cbdd137"

  strings:
    $s1 = "function _BAi2(s) {var _BDf5 = new Date();_BDf5.setUTCFullYear(\"2003\");if (_BDf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _BAi2(s) {var _BDf5 = new Date();_BDf5.setUTCFullYear(\"2003\");if (_BDf5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ej6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}