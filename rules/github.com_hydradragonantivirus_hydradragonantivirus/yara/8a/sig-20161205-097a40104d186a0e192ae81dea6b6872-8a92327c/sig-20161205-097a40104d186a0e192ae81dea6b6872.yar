rule sig_20161205_097a40104d186a0e192ae81dea6b6872 {
  meta:
    description = "datamaliciousorder - file 20161205_097a40104d186a0e192ae81dea6b6872.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40fc47a5b3ec4c1959e8f8201bea5536fdbcda9540224198e53d9cab6e5f5b5d"

  strings:
    $s1 = "function _Np6(s) {var _AGj9 = new Date();_AGj9.setUTCFullYear(\"2003\");if (_AGj9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Np6(s) {var _AGj9 = new Date();_AGj9.setUTCFullYear(\"2003\");if (_AGj9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _CIk7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}