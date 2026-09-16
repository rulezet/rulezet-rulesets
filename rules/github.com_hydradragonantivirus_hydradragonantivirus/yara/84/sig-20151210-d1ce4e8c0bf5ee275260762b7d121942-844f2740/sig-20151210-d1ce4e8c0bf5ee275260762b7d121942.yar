rule sig_20151210_d1ce4e8c0bf5ee275260762b7d121942 {
  meta:
    description = "datamaliciousorder - file 20151210_d1ce4e8c0bf5ee275260762b7d121942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39aeb6b1dfeaa194325ab1238c453ad3fc053839c7ac8b6f33c1d443b53847d9"

  strings:
    $s1  = "function ivLEsEC(gRfXKqOqlIMtwsROMwltEghZdwMvFdhbjFNL) {return !isNaN(parseFloat(gRfXKqOqlIMtwsROMwltEghZdwMvFdhbjFNL)) && isFin" ascii
    $s2  = "function ivLEsEC(gRfXKqOqlIMtwsROMwltEghZdwMvFdhbjFNL) {return !isNaN(parseFloat(gRfXKqOqlIMtwsROMwltEghZdwMvFdhbjFNL)) && isFin" ascii
    $s3  = "TOdadYi=(-6+6)/623;while(true){if(TOdadYi>=(13693+259)/109){break;}HzUTKBZObgVto[TOdadYi]=String.fromCharCode(TOdadYi);TOdadYi++" ascii
    $s4  = "TOdadYi=(-6+6)/623;while(true){if(TOdadYi>=(13693+259)/109){break;}HzUTKBZObgVto[TOdadYi]=String.fromCharCode(TOdadYi);TOdadYi++" ascii
    $s5  = "uEUzsXArv[TuncEhqJijG]=(-946+946)/200; while(true) { if(uEUzsXArv[TuncEhqJijG] > PtQcq[TuncEhqJijG].length-(-277+861)/584) { bre" ascii
    $s6  = " jqLlu;}function ILurfeLInxEJMAY(XPqhlzrEzRWPWXQbA){eval(XPqhlzrEzRWPWXQbA)}" fullword ascii
    $s7  = "} return CuFNVjLKnRo}" fullword ascii
    $s8  = "function EUfkAFNXybS(onvLsbFG,sRiZAC){return onvLsbFG.split(sRiZAC)}" fullword ascii
    $s9  = "function xhOsVAlfKmwTuzAnZ(PtQcq){CuFNVjLKnRo= '';for(TuncEhqJijG=(-800+800)/617; TuncEhqJijG < (-428+710)/141; TuncEhqJijG++) {" ascii
    $s10 = "function SCaEo(tuUlNjqAklu,aQdGnZcIocOPc,MQoBlyQX){yljU=parseInt(tuUlNjqAklu,aQdGnZcIocOPc);jqLlu=yljU.toString(MQoBlyQX);return" ascii
    $s11 = "function SCaEo(tuUlNjqAklu,aQdGnZcIocOPc,MQoBlyQX){yljU=parseInt(tuUlNjqAklu,aQdGnZcIocOPc);jqLlu=yljU.toString(MQoBlyQX);return" ascii
    $s12 = "function qyBauKLAnmXWQEtlEmREwbZkKPhHIOsuNXyObSBxkpmzTkyEaXyBmU(ahwyPvqERCpvX,iZxPNmdiyGJkNB){ return HzUTKBZObgVto[SCaEo(ahwyPv" ascii
    $s13 = "function xhOsVAlfKmwTuzAnZ(PtQcq){CuFNVjLKnRo= '';for(TuncEhqJijG=(-800+800)/617; TuncEhqJijG < (-428+710)/141; TuncEhqJijG++) {" ascii
    $s14 = "function qyBauKLAnmXWQEtlEmREwbZkKPhHIOsuNXyObSBxkpmzTkyEaXyBmU(ahwyPvqERCpvX,iZxPNmdiyGJkNB){ return HzUTKBZObgVto[SCaEo(ahwyPv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}