rule sig_20161205_989578ad83ce7165b6d4a9d72e02c785 {
  meta:
    description = "datamaliciousorder - file 20161205_989578ad83ce7165b6d4a9d72e02c785.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f397ee2d065c6fbc120c1662079f7804ff659c589d0f0bc39eb87739aab0375"

  strings:
    $s1 = "function _Rn2(s) {var _Mz7 = new Date();_Mz7.setUTCFullYear(\"2003\");if (_Mz7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rn2(s) {var _Mz7 = new Date();_Mz7.setUTCFullYear(\"2003\");if (_Mz7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _SFp1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}