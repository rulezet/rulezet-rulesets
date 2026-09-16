rule sig_20161205_eb8aafd3e6168212609ce3791e0a6da7 {
  meta:
    description = "datamaliciousorder - file 20161205_eb8aafd3e6168212609ce3791e0a6da7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec2b7108b30d04ad7cd5dd8c709692d88b6f91043627f1815a4c75f381e66db"

  strings:
    $s1 = "function _Fp5(s) {var _Xw9 = new Date();_Xw9.setUTCFullYear(\"2003\");if (_Xw9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Fp5(s) {var _Xw9 = new Date();_Xw9.setUTCFullYear(\"2003\");if (_Xw9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Nd4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}