rule sig_20161205_62742189a40451247407af5f9e3e4d47 {
  meta:
    description = "datamaliciousorder - file 20161205_62742189a40451247407af5f9e3e4d47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "884075a9a0e79699b9aac40ba50f2ec8dd961e5f39d61ca1b740ec28a0b57d3d"

  strings:
    $s1 = "function _Zk5(s) {var _Ds1 = new Date();_Ds1.setUTCFullYear(\"2003\");if (_Ds1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zk5(s) {var _Ds1 = new Date();_Ds1.setUTCFullYear(\"2003\");if (_Ds1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _TCs6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}