rule sig_20161205_50b19e74285d516a12f48f3c9b0e6d9f {
  meta:
    description = "datamaliciousorder - file 20161205_50b19e74285d516a12f48f3c9b0e6d9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ef64d2234a9915b16ec2414144cebb16223beae1c80552eb8a49a83af59633a"

  strings:
    $s1 = "function _Tv6(s) {var _Du3 = new Date();_Du3.setUTCFullYear(\"2003\");if (_Du3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Tv6(s) {var _Du3 = new Date();_Du3.setUTCFullYear(\"2003\");if (_Du3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ZCv8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}