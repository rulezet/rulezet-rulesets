rule sig_20160514_06cf38ea361ef380f337417dff1b3cf4 {
  meta:
    description = "datamaliciousorder - file 20160514_06cf38ea361ef380f337417dff1b3cf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ce63706a546075f6e0f96bc4d93df558c409c7d7ed92e521704bd9590947a76"

  strings:
    $s1  = "while (LcXe < Eyan - (4035 - 4033)) {" fullword ascii
    $s2  = "function gToX() {" fullword ascii
    $s3  = "return QEPYTz;" fullword ascii
    $s4  = "return mFyRU;" fullword ascii
    $s5  = "function qzus(Aho) {" fullword ascii
    $s6  = "function yxCF(lFcL) {" fullword ascii
    $s7  = "return hpKqj;" fullword ascii
    $s8  = "return DElhBmv;" fullword ascii
    $s9  = "function JoVLPM(mdvMa, BTtJ) {" fullword ascii
    $s10 = "return ejsL;" fullword ascii
    $s11 = "return NXguqy;" fullword ascii
    $s12 = "function Lhk(InS) {" fullword ascii
    $s13 = "function OugDf() {" fullword ascii
    $s14 = "function ycmE() {" fullword ascii
    $s15 = "function vaBpsJD(EaAXUO) {" fullword ascii
    $s16 = "function cvoOrDc(dfegg) {" fullword ascii
    $s17 = "function zzMdog() {" fullword ascii
    $s18 = "return WFwhRbFJ;" fullword ascii
    $s19 = "function ejboIdB(tuiyo, fmmd, kemn) {" fullword ascii
    $s20 = "return tupZtt;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}