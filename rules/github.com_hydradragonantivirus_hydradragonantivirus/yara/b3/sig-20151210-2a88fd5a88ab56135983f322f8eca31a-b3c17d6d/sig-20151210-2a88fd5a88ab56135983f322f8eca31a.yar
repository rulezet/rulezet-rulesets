rule sig_20151210_2a88fd5a88ab56135983f322f8eca31a {
  meta:
    description = "datamaliciousorder - file 20151210_2a88fd5a88ab56135983f322f8eca31a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afcd20c7e28b6a9c4264f5ca421ef106beed163e2818ae492df8b2771530a36b"

  strings:
    $s1  = "function yGIQLhn(myZeUYYIklxTiqiKNGPfRAxwVIUQpgWpSgaH) {return !isNaN(parseFloat(myZeUYYIklxTiqiKNGPfRAxwVIUQpgWpSgaH)) && isFin" ascii
    $s2  = "function yGIQLhn(myZeUYYIklxTiqiKNGPfRAxwVIUQpgWpSgaH) {return !isNaN(parseFloat(myZeUYYIklxTiqiKNGPfRAxwVIUQpgWpSgaH)) && isFin" ascii
    $s3  = "iBHHDIs=(-811+811)/870;while(true){if(iBHHDIs>=(55490+446)/437){break;}KvkseUaInsiPj[iBHHDIs]=String.fromCharCode(iBHHDIs);iBHHD" ascii
    $s4  = "function iPbyP(vOMtMYJLyoQ,qoiBuUzGaGJyz,VGypYhlW){OmpH=parseInt(vOMtMYJLyoQ,qoiBuUzGaGJyz);IZjFu=OmpH.toString(VGypYhlW);return" ascii
    $s5  = "function uUZHWvCqWfUORDZyQ(EjLAY){cIrIrqUrlWo= '';for(HvPwVfdOPeJ=(-861+861)/678; HvPwVfdOPeJ < (1015+713)/864; HvPwVfdOPeJ++) {" ascii
    $s6  = "function pUNXIurjGRygFIMfPAmessKeqAZFFetEwlQboIDBtKDeRHBopBxzBU(PnZkXJQFsAPjf,UjaEWNMeJyYNaE){ return KvkseUaInsiPj[iPbyP(PnZkXJ" ascii
    $s7  = "function UINTpgoBzKs(FhyJyRoC,UggNMH){return FhyJyRoC.split(UggNMH)}" fullword ascii
    $s8  = "function iPbyP(vOMtMYJLyoQ,qoiBuUzGaGJyz,VGypYhlW){OmpH=parseInt(vOMtMYJLyoQ,qoiBuUzGaGJyz);IZjFu=OmpH.toString(VGypYhlW);return" ascii
    $s9  = "iBHHDIs=(-811+811)/870;while(true){if(iBHHDIs>=(55490+446)/437){break;}KvkseUaInsiPj[iBHHDIs]=String.fromCharCode(iBHHDIs);iBHHD" ascii
    $s10 = "function uUZHWvCqWfUORDZyQ(EjLAY){cIrIrqUrlWo= '';for(HvPwVfdOPeJ=(-861+861)/678; HvPwVfdOPeJ < (1015+713)/864; HvPwVfdOPeJ++) {" ascii
    $s11 = " IZjFu;}function WsylfpnjqnoHRcW(brrmQpaQALGauOAwb){eval(brrmQpaQALGauOAwb)}" fullword ascii
    $s12 = ";}} return cIrIrqUrlWo}" fullword ascii
    $s13 = "lAPBpLUEm[HvPwVfdOPeJ]=(-540+540)/51; while(true) { if(lAPBpLUEm[HvPwVfdOPeJ] > EjLAY[HvPwVfdOPeJ].length-(-388+897)/509) { brea" ascii
    $s14 = "function pUNXIurjGRygFIMfPAmessKeqAZFFetEwlQboIDBtKDeRHBopBxzBU(PnZkXJQFsAPjf,UjaEWNMeJyYNaE){ return KvkseUaInsiPj[iPbyP(PnZkXJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}