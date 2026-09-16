rule sig_20161205_a38d222d87d068cd555bef1566154f8f {
  meta:
    description = "datamaliciousorder - file 20161205_a38d222d87d068cd555bef1566154f8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c8847eda04815d8be74d3bc462de2c08c653fe712639edc5144eb523cc205f"

  strings:
    $s1 = "function _VSz3(s) {var _KDl3 = new Date();_KDl3.setUTCFullYear(\"2003\");if (_KDl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VSz3(s) {var _KDl3 = new Date();_KDl3.setUTCFullYear(\"2003\");if (_KDl3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Az9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}