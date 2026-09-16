rule sig_20161205_24a3a04bcb042a1b03fb790f7247e854 {
  meta:
    description = "datamaliciousorder - file 20161205_24a3a04bcb042a1b03fb790f7247e854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67ce7da68c0bc45e450c384bdbe068d01641a33cd0fe056bfd302a5c86450e46"

  strings:
    $s1 = "function _Tr0(s) {var _Bq9 = new Date();_Bq9.setUTCFullYear(\"2003\");if (_Bq9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Tr0(s) {var _Bq9 = new Date();_Bq9.setUTCFullYear(\"2003\");if (_Bq9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _WIs6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}