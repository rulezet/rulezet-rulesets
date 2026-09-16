rule sig_20160902_9bc22a9874156f763e4257b41ade6f23 {
  meta:
    description = "datamaliciousorder - file 20160902_9bc22a9874156f763e4257b41ade6f23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a952d852fcb48b407ca4ba40964c55d46fe6da03cd6749ec730e71f09e7163af"

  strings:
    $s1  = "while (eXkPL < eNkIr - 2) {" fullword ascii
    $s2  = "var HwGI = new Array(ummG + \"r\" + MoCeEM);" fullword ascii
    $s3  = "function urZFJG() {" fullword ascii
    $s4  = "function yqvQIeh(rtwjdld, kdkndmd) {" fullword ascii
    $s5  = "return parZsFTJ;" fullword ascii
    $s6  = "function aiGoe(LaIELsrk) {" fullword ascii
    $s7  = "return EGafyr;" fullword ascii
    $s8  = "function LBSWtb(MfQ) {" fullword ascii
    $s9  = "function qjVP() {" fullword ascii
    $s10 = "return QJDx;" fullword ascii
    $s11 = "var ostY = String;" fullword ascii
    $s12 = "function mmRuQ(SqJROh) {" fullword ascii
    $s13 = "return bjXLO;" fullword ascii
    $s14 = "return DdBp;" fullword ascii
    $s15 = "function rxrh() {" fullword ascii
    $s16 = "function LGsdn(LOTKny, bvgNQbZ) {" fullword ascii
    $s17 = "return FDUVZK;" fullword ascii
    $s18 = "return viRB;" fullword ascii
    $s19 = "function xcYL() {" fullword ascii
    $s20 = "function Ofvjxu(str) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}