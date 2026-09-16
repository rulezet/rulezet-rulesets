rule sig_20161205_c032a0567ca1ded77dabbc68afdafdd9 {
  meta:
    description = "datamaliciousorder - file 20161205_c032a0567ca1ded77dabbc68afdafdd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd4dae2a51c590d9825ec565307d12854fb60a708dfaac231b6ae421b689cbdc"

  strings:
    $s1 = "function _Ux0(s) {var _Qt3 = new Date();_Qt3.setUTCFullYear(\"2003\");if (_Qt3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ux0(s) {var _Qt3 = new Date();_Qt3.setUTCFullYear(\"2003\");if (_Qt3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Pa1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}