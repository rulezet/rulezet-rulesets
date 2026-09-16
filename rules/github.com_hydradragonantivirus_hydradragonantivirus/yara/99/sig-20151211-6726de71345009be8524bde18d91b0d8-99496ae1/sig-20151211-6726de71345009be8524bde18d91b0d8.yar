rule sig_20151211_6726de71345009be8524bde18d91b0d8 {
  meta:
    description = "datamaliciousorder - file 20151211_6726de71345009be8524bde18d91b0d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1665fac9048319545f8d1dfc73bdb12a072489e1281bd2d5b59c1f616df457"

  strings:
    $s1  = "function BgaASnK(rSRvgKjyfoMFBjbnrKveqPGgfUZZKXkZCnGj) {return !isNaN(parseFloat(rSRvgKjyfoMFBjbnrKveqPGgfUZZKXkZCnGj)) && isFin" ascii
    $s2  = "function BgaASnK(rSRvgKjyfoMFBjbnrKveqPGgfUZZKXkZCnGj) {return !isNaN(parseFloat(rSRvgKjyfoMFBjbnrKveqPGgfUZZKXkZCnGj)) && isFin" ascii
    $s3  = "function zVKcsBLrKJrNZaIujlezbQyOrQMpjyKVgAmLKjmJXgZrQMIYtxeYsW(DFAUKqAYiEmui,iXJOZZJAvlNsHp){ return cqufc[yxBfL(DFAUKqAYiEmui[" ascii
    $s4  = "+;}pgiqUKmZzeE++;} return RdfdUKhjaVz}" fullword ascii
    $s5  = "function yxBfL(aBVtNhLKmnh,wTzMMvstUDqIh,BIcLlcxM){BSOV=parseInt(aBVtNhLKmnh,wTzMMvstUDqIh);keLUm=BSOV.toString(BIcLlcxM);return" ascii
    $s6  = "function TJBNoLEJpsZ(jkwTDMeq,EMwqaJ){return jkwTDMeq.split(EMwqaJ)}" fullword ascii
    $s7  = "function zVKcsBLrKJrNZaIujlezbQyOrQMpjyKVgAmLKjmJXgZrQMIYtxeYsW(DFAUKqAYiEmui,iXJOZZJAvlNsHp){ return cqufc[yxBfL(DFAUKqAYiEmui[" ascii
    $s8  = "function ksRHdBxXzytPSutZe(wxwBP){RdfdUKhjaVz= '';pgiqUKmZzeE=(-263+263)/385; while(true){if(pgiqUKmZzeE >= (200+428)/314)break;" ascii
    $s9  = "function ksRHdBxXzytPSutZe(wxwBP){RdfdUKhjaVz= '';pgiqUKmZzeE=(-263+263)/385; while(true){if(pgiqUKmZzeE >= (200+428)/314)break;" ascii
    $s10 = "var n=new Array(\"28\",\"2c\",\"29\",\"2e\",\"2c\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"53\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"53\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "function yxBfL(aBVtNhLKmnh,wTzMMvstUDqIh,BIcLlcxM){BSOV=parseInt(aBVtNhLKmnh,wTzMMvstUDqIh);keLUm=BSOV.toString(BIcLlcxM);return" ascii
    $s14 = "KCHcEIcWM[pgiqUKmZzeE]=(-189+189)/721; while(true) { if(KCHcEIcWM[pgiqUKmZzeE] > wxwBP[pgiqUKmZzeE].length-(-58+285)/227) { brea" ascii
    $s15 = " keLUm;}function mIpgHIwEsRyjqvW(mffarPtJsObstFwMR){eval(mffarPtJsObstFwMR)}" fullword ascii
    $s16 = "var n=new Array(\"28\",\"2c\",\"29\",\"2e\",\"2c\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}