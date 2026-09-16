rule sig_20160514_3e849219c00cf9b2daa9afe12612ba61 {
  meta:
    description = "datamaliciousorder - file 20160514_3e849219c00cf9b2daa9afe12612ba61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9727f70399e98fa9129a0193c3570e58fab3fbd87bc872cc8e66d7e0fb26f20c"

  strings:
    $s1  = "while (oEjOFC < evrLdMV - (2910 - 2908)) {" fullword ascii
    $s2  = "function WFw() {" fullword ascii
    $s3  = "return Fksmsih;" fullword ascii
    $s4  = "return rfLfUQK;" fullword ascii
    $s5  = "function zQLxbzm(dfegg) {" fullword ascii
    $s6  = "function PuMHjLW() {" fullword ascii
    $s7  = "return NOeF;" fullword ascii
    $s8  = "return Wyxiz;" fullword ascii
    $s9  = "function SjQzC() {" fullword ascii
    $s10 = "function bIxna() {" fullword ascii
    $s11 = "function vxo() {" fullword ascii
    $s12 = "return vTmwQABi;" fullword ascii
    $s13 = "function aXMv() {" fullword ascii
    $s14 = "return uLUIMv;" fullword ascii
    $s15 = "return ZMTmky;" fullword ascii
    $s16 = "mrya = true;" fullword ascii
    $s17 = "function CfbJb(DQevqBHj, kPhfmgVQ) {" fullword ascii
    $s18 = "function fDxny(Dfhzy) {" fullword ascii
    $s19 = "var Illi = false;" fullword ascii
    $s20 = "return GFDAy;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}