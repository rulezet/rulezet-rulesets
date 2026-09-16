rule sig_20160514_77c8c793b304379fa8f37e92202c693b {
  meta:
    description = "datamaliciousorder - file 20160514_77c8c793b304379fa8f37e92202c693b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d088fe3ca370d1a98f19c315be5cfb9d377d3ae5e68c3277e98c58b02e4e5535"

  strings:
    $s1  = "while (kfOHtz < cejwfdU - (8624 + 1805 - 10427)) {" fullword ascii
    $s2  = "return LnZesCH;" fullword ascii
    $s3  = "return lxOPmx;" fullword ascii
    $s4  = "function YODX() {" fullword ascii
    $s5  = "function PeqZ() {" fullword ascii
    $s6  = "function hiHWLF() {" fullword ascii
    $s7  = "function bYn(HHqEs) {" fullword ascii
    $s8  = "function JyTHnKH(zfMns, sdf, spc) {" fullword ascii
    $s9  = "return UKghyfs;" fullword ascii
    $s10 = "function bYeEG() {" fullword ascii
    $s11 = "return eVNh;" fullword ascii
    $s12 = "return ZjwOnT;" fullword ascii
    $s13 = "var LusK = \"c\";" fullword ascii
    $s14 = "return LPYsFRM;" fullword ascii
    $s15 = "function bwMmX() {" fullword ascii
    $s16 = "function HQTu(tuiyo, fmmd, kemn) {" fullword ascii
    $s17 = "function QWulZr(OdXUPmZx) {" fullword ascii
    $s18 = "function umesTpJ() {" fullword ascii
    $s19 = "return PWajuwiE;" fullword ascii
    $s20 = "function qirf(Hqj, XSv) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}