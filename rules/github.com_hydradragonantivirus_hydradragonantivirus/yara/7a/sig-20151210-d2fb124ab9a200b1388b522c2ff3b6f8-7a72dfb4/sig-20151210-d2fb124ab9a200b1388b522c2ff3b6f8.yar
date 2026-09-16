rule sig_20151210_d2fb124ab9a200b1388b522c2ff3b6f8 {
  meta:
    description = "datamaliciousorder - file 20151210_d2fb124ab9a200b1388b522c2ff3b6f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b7a7bf62edae0d83e492aadf03ca4a46fc125038c98a2ade427e91983e4a23e"

  strings:
    $s1  = "function oeEjEsf(UXSlWMQACCVHImcyrDaGWNLrEYTiwbKuQXkb) {return !isNaN(parseFloat(UXSlWMQACCVHImcyrDaGWNLrEYTiwbKuQXkb)) && isFin" ascii
    $s2  = "function oeEjEsf(UXSlWMQACCVHImcyrDaGWNLrEYTiwbKuQXkb) {return !isNaN(parseFloat(UXSlWMQACCVHImcyrDaGWNLrEYTiwbKuQXkb)) && isFin" ascii
    $s3  = "kvubprY[QPkvanGxcyB]=(-795+795)/987; while(true) { if(gbkvubprY[QPkvanGxcyB] > KAfcc[QPkvanGxcyB].length-(75+312)/387) { break; " ascii
    $s4  = "function zUfdaijaYIvHiQSuR(KAfcc){rPhfgdEInzP= '';for(QPkvanGxcyB=(-390+390)/788; QPkvanGxcyB < (761+59)/410; QPkvanGxcyB++) {gb" ascii
    $s5  = "function ihAMq(bBxWrKBPihH,tHOuENEFcngin,cnRseTsg){lUac=parseInt(bBxWrKBPihH,tHOuENEFcngin);TerEa=lUac.toString(cnRseTsg);return" ascii
    $s6  = "function AnULsRUONQPKpzOlSuuWusddZnuKusxbNRjEdnwsawJJJcSJAlGdQR(XPNwmTtxzymgg,dRSkRxkCDVDYhk){ return JyzUlXDclvbBN[ihAMq(XPNwmT" ascii
    $s7  = " TerEa;}function SZsqbTBCVMXYWXh(MRBmyTEhhuwfotzVD){eval(MRBmyTEhhuwfotzVD)}" fullword ascii
    $s8  = "function ihAMq(bBxWrKBPihH,tHOuENEFcngin,cnRseTsg){lUac=parseInt(bBxWrKBPihH,tHOuENEFcngin);TerEa=lUac.toString(cnRseTsg);return" ascii
    $s9  = "function aASjzZJHjDC(oIciWvUb,gaQkPk){return oIciWvUb.split(gaQkPk)}" fullword ascii
    $s10 = "function AnULsRUONQPKpzOlSuuWusddZnuKusxbNRjEdnwsawJJJcSJAlGdQR(XPNwmTtxzymgg,dRSkRxkCDVDYhk){ return JyzUlXDclvbBN[ihAMq(XPNwmT" ascii
    $s11 = "function zUfdaijaYIvHiQSuR(KAfcc){rPhfgdEInzP= '';for(QPkvanGxcyB=(-390+390)/788; QPkvanGxcyB < (761+59)/410; QPkvanGxcyB++) {gb" ascii
    $s12 = "KNXIEws=(-56+56)/367;while(true){if(KNXIEws>=(85129+759)/671){break;}JyzUlXDclvbBN[KNXIEws]=String.fromCharCode(KNXIEws);KNXIEws" ascii
    $s13 = " return rPhfgdEInzP}" fullword ascii
    $s14 = "KNXIEws=(-56+56)/367;while(true){if(KNXIEws>=(85129+759)/671){break;}JyzUlXDclvbBN[KNXIEws]=String.fromCharCode(KNXIEws);KNXIEws" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}