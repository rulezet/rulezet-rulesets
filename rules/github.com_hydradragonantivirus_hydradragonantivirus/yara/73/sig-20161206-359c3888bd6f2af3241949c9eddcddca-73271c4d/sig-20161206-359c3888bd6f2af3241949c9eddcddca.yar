rule sig_20161206_359c3888bd6f2af3241949c9eddcddca {
  meta:
    description = "datamaliciousorder - file 20161206_359c3888bd6f2af3241949c9eddcddca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ced9e6bdaeaff7bff9fb22c9e14e04bb911c58a08b8597548da33b1b847bf7bf"

  strings:
    $s1 = "function _Wd6(s) {var _Jd8 = new Date();_Jd8.setUTCFullYear(\"2003\");if (_Jd8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wd6(s) {var _Jd8 = new Date();_Jd8.setUTCFullYear(\"2003\");if (_Jd8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PPl1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}