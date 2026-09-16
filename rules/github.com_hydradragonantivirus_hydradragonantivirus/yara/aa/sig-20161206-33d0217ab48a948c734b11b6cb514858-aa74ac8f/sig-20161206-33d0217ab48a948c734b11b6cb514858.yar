rule sig_20161206_33d0217ab48a948c734b11b6cb514858 {
  meta:
    description = "datamaliciousorder - file 20161206_33d0217ab48a948c734b11b6cb514858.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcf13c3b04bdcab0b87a85678ab45e6f0b93e80193dd7496e8fe59913a1e887b"

  strings:
    $s1 = "function _Sj0(s) {var _Ni8 = new Date();_Ni8.setUTCFullYear(\"2003\");if (_Ni8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Sj0(s) {var _Ni8 = new Date();_Ni8.setUTCFullYear(\"2003\");if (_Ni8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Vi4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}