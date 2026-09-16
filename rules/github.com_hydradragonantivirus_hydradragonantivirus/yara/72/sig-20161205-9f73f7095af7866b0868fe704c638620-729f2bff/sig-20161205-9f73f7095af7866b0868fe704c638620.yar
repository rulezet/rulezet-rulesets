rule sig_20161205_9f73f7095af7866b0868fe704c638620 {
  meta:
    description = "datamaliciousorder - file 20161205_9f73f7095af7866b0868fe704c638620.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3458caaa9c1654527a45a13870814556e1be2125a75a8698f3c49d534b0612e5"

  strings:
    $s1 = "function _Zz4(s) {var _Dn9 = new Date();_Dn9.setUTCFullYear(\"2003\");if (_Dn9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Zz4(s) {var _Dn9 = new Date();_Dn9.setUTCFullYear(\"2003\");if (_Dn9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _RQp3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}