rule sig_20160514_c16cd4ed5cb4815bd8bdcd34bb10fbc4 {
  meta:
    description = "datamaliciousorder - file 20160514_c16cd4ed5cb4815bd8bdcd34bb10fbc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f81944ef6e64fa6b1354bb8bb2003d8b1c7721f8b27fef131a0680e0f2423de6"

  strings:
    $s1  = "while (sFdSPtBs < NFnBq - (7932 - 7930)) {" fullword ascii
    $s2  = "function nCebKda(FOGfJC, vfhsGy) {" fullword ascii
    $s3  = "return sOuv;" fullword ascii
    $s4  = "return VmpHmd;" fullword ascii
    $s5  = "return AkqI;" fullword ascii
    $s6  = "return iIyYj;" fullword ascii
    $s7  = "function xfNDagz() {" fullword ascii
    $s8  = "function MHp() {" fullword ascii
    $s9  = "var IfBUseW = String;" fullword ascii
    $s10 = "return ZMhylVch;" fullword ascii
    $s11 = "function nPwMh(yeopxwMW, MXDR) {" fullword ascii
    $s12 = "function uMr(jCM) {" fullword ascii
    $s13 = "return jYoYV;" fullword ascii
    $s14 = "return HgKCocBm;" fullword ascii
    $s15 = "function JIVqeyb(XgXlvvHi) {" fullword ascii
    $s16 = "return rATJUPP;" fullword ascii
    $s17 = "function MOJWkG() {" fullword ascii
    $s18 = "function LjzdJjs(tuiyo, fmmd, kemn) {" fullword ascii
    $s19 = "function VgeS() {" fullword ascii
    $s20 = "function ZIyT() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}