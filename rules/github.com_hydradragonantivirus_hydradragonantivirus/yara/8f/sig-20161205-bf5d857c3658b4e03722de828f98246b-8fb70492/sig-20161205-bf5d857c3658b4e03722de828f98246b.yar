rule sig_20161205_bf5d857c3658b4e03722de828f98246b {
  meta:
    description = "datamaliciousorder - file 20161205_bf5d857c3658b4e03722de828f98246b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d84086aa33e3ff97cc70311fad31be19d699fe04a94632ded7f0532eced11cf"

  strings:
    $s1 = "function _XZz5(s) {var _Bv7 = new Date();_Bv7.setUTCFullYear(\"2003\");if (_Bv7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _XZz5(s) {var _Bv7 = new Date();_Bv7.setUTCFullYear(\"2003\");if (_Bv7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _YSf1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}