rule sig_20151209_eec0e22a0cbf6596854198e5ddc26992 {
  meta:
    description = "datamaliciousorder - file 20151209_eec0e22a0cbf6596854198e5ddc26992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd8b21c42d08f07cdd2d37bccf446982293674b2384d51caf2b316b116634273"

  strings:
    $s1  = "function NuGsSiX(fTfcJXlZFVpfepZwJUTbobcpqZvkPTXvZctQ) {return !isNaN(parseFloat(fTfcJXlZFVpfepZwJUTbobcpqZvkPTXvZctQ)) && isFin" ascii
    $s2  = "function NuGsSiX(fTfcJXlZFVpfepZwJUTbobcpqZvkPTXvZctQ) {return !isNaN(parseFloat(fTfcJXlZFVpfepZwJUTbobcpqZvkPTXvZctQ)) && isFin" ascii
    $s3  = "wqljCVd[mjAdpZhGKzx]=(-567+567)/724; while(true) { if(gswqljCVd[mjAdpZhGKzx] > gaTtL[mjAdpZhGKzx].length-(458+16)/474) { break; " ascii
    $s4  = "function ZyBeRtjubtS(fiJmLTPP,eiHBtw){return fiJmLTPP.split(eiHBtw)}" fullword ascii
    $s5  = "function GpjUHjnQsazWRiajS(gaTtL){vGxvWUDPLSW= '';for(mjAdpZhGKzx=(-191+191)/88; mjAdpZhGKzx < (1022+66)/544; mjAdpZhGKzx++) {gs" ascii
    $s6  = "function BJngi(tfqQKciANgY,pLcEFVCxiWatu,HDhpcVla){yxAx=parseInt(tfqQKciANgY,pLcEFVCxiWatu);MAixd=yxAx.toString(HDhpcVla);return" ascii
    $s7  = "}} return vGxvWUDPLSW}" fullword ascii
    $s8  = "function IfWmJrNfpCSWAANHnMOvaqZwEcAcKrHCZLGBTrofDZXjigMuNaRwIT(nucNtKuxDdKbk,SknTAvIzEwVSTJ){ return AYxIw[BJngi(nucNtKuxDdKbk[" ascii
    $s9  = "function BJngi(tfqQKciANgY,pLcEFVCxiWatu,HDhpcVla){yxAx=parseInt(tfqQKciANgY,pLcEFVCxiWatu);MAixd=yxAx.toString(HDhpcVla);return" ascii
    $s10 = "function IfWmJrNfpCSWAANHnMOvaqZwEcAcKrHCZLGBTrofDZXjigMuNaRwIT(nucNtKuxDdKbk,SknTAvIzEwVSTJ){ return AYxIw[BJngi(nucNtKuxDdKbk[" ascii
    $s11 = "function GpjUHjnQsazWRiajS(gaTtL){vGxvWUDPLSW= '';for(mjAdpZhGKzx=(-191+191)/88; mjAdpZhGKzx < (1022+66)/544; mjAdpZhGKzx++) {gs" ascii
    $s12 = " MAixd;}function FrQjEwChEDvwHaB(BuqgJgbMtewcadFBO){eval(BuqgJgbMtewcadFBO)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}