rule sig_20161205_2a94b85fad1be183f95418724b8ab02a {
  meta:
    description = "datamaliciousorder - file 20161205_2a94b85fad1be183f95418724b8ab02a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a4d593e66e5509f4bd1dce7dab21a77e9079fef3f1412fbc4f4774f00e5c04f"

  strings:
    $s1 = "function _JRo4(s) {var _Ni2 = new Date();_Ni2.setUTCFullYear(\"2003\");if (_Ni2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JRo4(s) {var _Ni2 = new Date();_Ni2.setUTCFullYear(\"2003\");if (_Ni2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Th7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}