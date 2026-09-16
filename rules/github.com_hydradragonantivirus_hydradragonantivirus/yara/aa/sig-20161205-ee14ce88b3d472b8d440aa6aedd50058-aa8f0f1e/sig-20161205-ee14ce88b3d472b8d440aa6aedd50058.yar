rule sig_20161205_ee14ce88b3d472b8d440aa6aedd50058 {
  meta:
    description = "datamaliciousorder - file 20161205_ee14ce88b3d472b8d440aa6aedd50058.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6685b30ca11ec4c38a0b40212e318738e900bc56bb07d7bb91771e90c9783515"

  strings:
    $s1 = "function _Be2(s) {var _Pf5 = new Date();_Pf5.setUTCFullYear(\"2003\");if (_Pf5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Be2(s) {var _Pf5 = new Date();_Pf5.setUTCFullYear(\"2003\");if (_Pf5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _AXs3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}