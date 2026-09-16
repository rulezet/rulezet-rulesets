rule sig_20151211_fc72c78567e802ff66d5426343c05bd3 {
  meta:
    description = "datamaliciousorder - file 20151211_fc72c78567e802ff66d5426343c05bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad4aa68a99c7f8243bf52ded3909c2e71518e806a31c7b3239113c2895f5c15b"

  strings:
    $s1  = "function WmEFBVy(OXayvPzozaEdXHhuzhjMMtnPXGDOrvaCqtOk) {return !isNaN(parseFloat(OXayvPzozaEdXHhuzhjMMtnPXGDOrvaCqtOk)) && isFin" ascii
    $s2  = "function WmEFBVy(OXayvPzozaEdXHhuzhjMMtnPXGDOrvaCqtOk) {return !isNaN(parseFloat(OXayvPzozaEdXHhuzhjMMtnPXGDOrvaCqtOk)) && isFin" ascii
    $s3  = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function DJMqyZwRIqkaNywlT(cSYQl){bqODoVTyIkl= '';RumGprGgJuK=(-66+66)/139; while(true){if(RumGprGgJuK >= (1466+448)/957)break;o" ascii
    $s5  = "var P=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function zkEAG(EQcWucPIImL,qfFhxKMBcrNzk,cviOZEMZ){wuJs=parseInt(EQcWucPIImL,qfFhxKMBcrNzk);tQDIN=wuJs.toString(cviOZEMZ);return" ascii
    $s7  = "function XpHNeYTNQhV(xswmBXlw,FUzAkt){return xswmBXlw.split(FUzAkt)}" fullword ascii
    $s8  = "+;}RumGprGgJuK++;} return bqODoVTyIkl}" fullword ascii
    $s9  = "function DJMqyZwRIqkaNywlT(cSYQl){bqODoVTyIkl= '';RumGprGgJuK=(-66+66)/139; while(true){if(RumGprGgJuK >= (1466+448)/957)break;o" ascii
    $s10 = " tQDIN;}function WpPZgmNRBAFVngW(NiXyYhDNvZDVnqAEX){eval(NiXyYhDNvZDVnqAEX)}" fullword ascii
    $s11 = "function zkEAG(EQcWucPIImL,qfFhxKMBcrNzk,cviOZEMZ){wuJs=parseInt(EQcWucPIImL,qfFhxKMBcrNzk);tQDIN=wuJs.toString(cviOZEMZ);return" ascii
    $s12 = "tKmunfqW[RumGprGgJuK]=(-166+166)/159; while(true) { if(otKmunfqW[RumGprGgJuK] > cSYQl[RumGprGgJuK].length-(-359+656)/297) { brea" ascii
    $s13 = "var t=new Array(\"27\",\"2a\",\"2f\",\"26\",\"28\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = "var t=new Array(\"27\",\"2a\",\"2f\",\"26\",\"28\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s15 = "function pHwhLVkNADcigjbkuiHUwlpFMpLOWcXgWssYcMHscfZWwsCJkrImpl(QWIFSWsoAUIDL,nbLGnZzQKemMKV){ return hvxgk[zkEAG(QWIFSWsoAUIDL[" ascii
    $s16 = "function pHwhLVkNADcigjbkuiHUwlpFMpLOWcXgWssYcMHscfZWwsCJkrImpl(QWIFSWsoAUIDL,nbLGnZzQKemMKV){ return hvxgk[zkEAG(QWIFSWsoAUIDL[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}