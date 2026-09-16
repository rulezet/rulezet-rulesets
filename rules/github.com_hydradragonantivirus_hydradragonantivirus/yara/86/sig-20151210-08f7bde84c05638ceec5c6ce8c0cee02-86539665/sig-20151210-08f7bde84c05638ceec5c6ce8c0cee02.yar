rule sig_20151210_08f7bde84c05638ceec5c6ce8c0cee02 {
  meta:
    description = "datamaliciousorder - file 20151210_08f7bde84c05638ceec5c6ce8c0cee02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42947468d09bdf760327bd15ab55da6f989822feb7c96251464e08913eae7b5c"

  strings:
    $s1  = "function UyZOr(sGKJeYhrNrq,COmYzYFGddFIw,grnKhfzP){hvBp=parseInt(sGKJeYhrNrq,COmYzYFGddFIw);SocJY=hvBp.toString(grnKhfzP);return" ascii
    $s2  = " SocJY;}function EClFzSEfhhQUqeF(KuUQywLVfruNKlbZk){eval(KuUQywLVfruNKlbZk)}" fullword ascii
    $s3  = "function SkXKacp(iliNQaxPmDkaNTPphMzowFwZkdkeomFmNtfS) {return !isNaN(parseFloat(iliNQaxPmDkaNTPphMzowFwZkdkeomFmNtfS)) && isFin" ascii
    $s4  = "function SkXKacp(iliNQaxPmDkaNTPphMzowFwZkdkeomFmNtfS) {return !isNaN(parseFloat(iliNQaxPmDkaNTPphMzowFwZkdkeomFmNtfS)) && isFin" ascii
    $s5  = "function UyZOr(sGKJeYhrNrq,COmYzYFGddFIw,grnKhfzP){hvBp=parseInt(sGKJeYhrNrq,COmYzYFGddFIw);SocJY=hvBp.toString(grnKhfzP);return" ascii
    $s6  = "bcOkumm=(-981+981)/413;while(true){if(bcOkumm>=(82816+0)/647){break;}UemiVbYDVGfeo[bcOkumm]=String.fromCharCode(bcOkumm);bcOkumm" ascii
    $s7  = "function XWDgXThtnjOvrpPmt(tyiJq){RnLfMLjmtFW= '';for(aelnkqDCQVR=(-62+62)/799; aelnkqDCQVR < (271+903)/587; aelnkqDCQVR++) {KdW" ascii
    $s8  = "} return RnLfMLjmtFW}" fullword ascii
    $s9  = "AKcfCI[aelnkqDCQVR]=(-975+975)/669; while(true) { if(KdWAKcfCI[aelnkqDCQVR] > tyiJq[aelnkqDCQVR].length-(-31+589)/558) { break; " ascii
    $s10 = "function lnuehEPaSaAgvTkRxnlqbkpLrtdmDzvudIVStWNWOpEuaMWXPUVAxB(QqTQADQOGBuIj,jkJaYIitCEmBme){ return UemiVbYDVGfeo[UyZOr(QqTQAD" ascii
    $s11 = "function XWDgXThtnjOvrpPmt(tyiJq){RnLfMLjmtFW= '';for(aelnkqDCQVR=(-62+62)/799; aelnkqDCQVR < (271+903)/587; aelnkqDCQVR++) {KdW" ascii
    $s12 = "function lnuehEPaSaAgvTkRxnlqbkpLrtdmDzvudIVStWNWOpEuaMWXPUVAxB(QqTQADQOGBuIj,jkJaYIitCEmBme){ return UemiVbYDVGfeo[UyZOr(QqTQAD" ascii
    $s13 = "function XBaUvWZGuxQ(JIaAdUlu,nicgZi){return JIaAdUlu.split(nicgZi)}" fullword ascii
    $s14 = "bcOkumm=(-981+981)/413;while(true){if(bcOkumm>=(82816+0)/647){break;}UemiVbYDVGfeo[bcOkumm]=String.fromCharCode(bcOkumm);bcOkumm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}