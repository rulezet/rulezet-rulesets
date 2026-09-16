rule sig_20161205_ae9fa050e2b172e85e8790ab1345c510 {
  meta:
    description = "datamaliciousorder - file 20161205_ae9fa050e2b172e85e8790ab1345c510.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388cb6a3b261c9a7557905950e2717365461fce1736ce6d8eaf4bb64bd3fc2bc"

  strings:
    $s1 = "function _MVb3(s) {var _FFb5 = new Date();_FFb5.setUTCFullYear(\"2003\");if (_FFb5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MVb3(s) {var _FFb5 = new Date();_FFb5.setUTCFullYear(\"2003\");if (_FFb5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _OPg8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}