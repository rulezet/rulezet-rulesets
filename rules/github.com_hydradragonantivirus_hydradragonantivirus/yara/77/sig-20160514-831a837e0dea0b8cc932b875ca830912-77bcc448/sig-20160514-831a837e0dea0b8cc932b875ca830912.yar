rule sig_20160514_831a837e0dea0b8cc932b875ca830912 {
  meta:
    description = "datamaliciousorder - file 20160514_831a837e0dea0b8cc932b875ca830912.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eb37180ca13f4f522d6fdca1c767ed5f9dd482c89f65b8f73c4ceefef89c8e4"

  strings:
    $s1  = "while (QfprDP < HJMUu - (981 - 979)) {" fullword ascii
    $s2  = "return jzMeyE;" fullword ascii
    $s3  = "return leaRwlF;" fullword ascii
    $s4  = "function Sya(xBiwtLXa, muFrpjm) {" fullword ascii
    $s5  = "function iXTZ(tuiyo, fmmd, kemn) {" fullword ascii
    $s6  = "function kiHGot(uLnekUq, FkKiv) {" fullword ascii
    $s7  = "function FcNypuE() {" fullword ascii
    $s8  = "function RfXggZA() {" fullword ascii
    $s9  = "return xwvWi;" fullword ascii
    $s10 = "function NKMp() {" fullword ascii
    $s11 = "return tnmKX;" fullword ascii
    $s12 = "function KUQkH() {" fullword ascii
    $s13 = "function cZFNnK(rtwjdld, kdkndmd) {" fullword ascii
    $s14 = "if (ZZVNN === false) {" fullword ascii
    $s15 = "function yNH(EYs) {" fullword ascii
    $s16 = "return qKXeZHCU;" fullword ascii
    $s17 = "var WFsCIdG = true;" fullword ascii
    $s18 = "var ZZVNN = false;" fullword ascii
    $s19 = "return WxNiwyQ[EYs];" fullword ascii
    $s20 = "function XdlqiFo() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}