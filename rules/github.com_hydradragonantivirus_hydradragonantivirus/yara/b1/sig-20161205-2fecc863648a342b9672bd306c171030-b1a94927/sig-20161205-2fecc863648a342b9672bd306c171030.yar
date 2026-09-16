rule sig_20161205_2fecc863648a342b9672bd306c171030 {
  meta:
    description = "datamaliciousorder - file 20161205_2fecc863648a342b9672bd306c171030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0be5f4801e8644aea20ade1a2d8b3bbe19d6fea5d2ca8c04d1fe74d36cd3f5a"

  strings:
    $s1 = "function _Nu8(s) {var _Yf0 = new Date();_Yf0.setUTCFullYear(\"2003\");if (_Yf0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Nu8(s) {var _Yf0 = new Date();_Yf0.setUTCFullYear(\"2003\");if (_Yf0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sl3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}