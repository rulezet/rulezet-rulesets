rule sig_20161205_87c883f178eff7da612b3b0528cda725 {
  meta:
    description = "datamaliciousorder - file 20161205_87c883f178eff7da612b3b0528cda725.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd2a592c96cffdc5ab59ba8d855ff9f38e2dce506e8716488e36b88b686643e"

  strings:
    $s1 = "function _BCf0(s) {var _Jd9 = new Date();_Jd9.setUTCFullYear(\"2003\");if (_Jd9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BCf0(s) {var _Jd9 = new Date();_Jd9.setUTCFullYear(\"2003\");if (_Jd9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Xp0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}