rule sig_20161205_81be3f6d47ef70a71bf5fe1c6cd8c96e {
  meta:
    description = "datamaliciousorder - file 20161205_81be3f6d47ef70a71bf5fe1c6cd8c96e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2716ad51704c87fd12139cfc8e1d16df8e6694840ff7084f290a795a1b62d00f"

  strings:
    $s1 = "function _KHy8(s) {var _CPu9 = new Date();_CPu9.setUTCFullYear(\"2003\");if (_CPu9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KHy8(s) {var _CPu9 = new Date();_CPu9.setUTCFullYear(\"2003\");if (_CPu9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MXp5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}