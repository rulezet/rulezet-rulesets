rule sig_20151217_6e537de815a21b31421c3e9793b3be95 {
  meta:
    description = "datamaliciousorder - file 20151217_6e537de815a21b31421c3e9793b3be95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58672a520e1a649efb14a28b92586f0ad3e66978c08beaf4740542775c3afcf8"

  strings:
    $s1  = "th.pow(Math.cos(522), 2) - 1)); while(true) { if(PEWeLQIkD[dLGBehiUqIB] > cPNnb[dLGBehiUqIB].length-(-255+496)/241) { break; } i" ascii
    $s2  = "function DaeicrOnUrhioMmLK(cPNnb){lHgvluEcOaS= '';dLGBehiUqIB=Math.round((Math.pow(Math.sin(114), 2) + Math.pow(Math.cos(114), 2" ascii
    $s3  = "pow(Math.cos(117), 2) - 1)));} PEWeLQIkD[dLGBehiUqIB]++;}dLGBehiUqIB++;} return lHgvluEcOaS}" fullword ascii
    $s4  = ") - 1));while(true){if (dLGBehiUqIB >= (3431+739)/695){break;}PEWeLQIkD[dLGBehiUqIB]=Math.round((Math.pow(Math.sin(522), 2) + Ma" ascii
    $s5  = "XXShFcdPRkTOWQfbtDNpNGIhtPwxKXCbmdq([cPNnb[dLGBehiUqIB][PEWeLQIkD[dLGBehiUqIB]]], Math.round((Math.pow(Math.sin(117), 2) + Math." ascii
    $s6  = "function DaeicrOnUrhioMmLK(cPNnb){lHgvluEcOaS= '';dLGBehiUqIB=Math.round((Math.pow(Math.sin(114), 2) + Math.pow(Math.cos(114), 2" ascii
    $s7  = "function qKeFQqi(sZBwtCiEkaWGiPtIklzxyRPVCFSnqNDVjDDY) {return !VnxksxkagHA(QZndcirHJCNNTaR(sZBwtCiEkaWGiPtIklzxyRPVCFSnqNDVjDDY" ascii
    $s8  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s9  = "function qKeFQqi(sZBwtCiEkaWGiPtIklzxyRPVCFSnqNDVjDDY) {return !VnxksxkagHA(QZndcirHJCNNTaR(sZBwtCiEkaWGiPtIklzxyRPVCFSnqNDVjDDY" ascii
    $s10 = "function QZndcirHJCNNTaR(JfsiCGRVVrdLvAxGiaq) {return parseFloat(JfsiCGRVVrdLvAxGiaq);}" fullword ascii
    $s11 = "function JSTNYnfqsPTggYy(kdVIDAAlVXgwPpLzR,sWrktogMvfjmkXfbaHmyhGAFtcVnrqrQyJ,NUIFheoDgjeSkgcmRHfdlGPgtbKEOfhweAU){eval(kdVIDAAl" ascii
    $s12 = "function YFxZvetsMayi(vLPHYVCnnHrTY) {return isFinite(vLPHYVCnnHrTY);}" fullword ascii
    $s13 = "function sWzjF(atlwJDXYonx,KVtNuYzupinjV,lUhOapBZ){yTiX=xPgwJPtFyAqUiqHzi(atlwJDXYonx,KVtNuYzupinjV);EruWx=yTiX.toString(lUhOapB" ascii
    $s14 = "function VnxksxkagHA(QIbEPBSZlRmgEm) {return isNaN(QIbEPBSZlRmgEm);}" fullword ascii
    $s15 = "function T(AEomMOMZuVPE,hSAtuOQyTqFOWK){AEomMOMZuVPE.push(hSAtuOQyTqFOWK);}" fullword ascii
    $s16 = "function kqmxREbqvXagzEoKOnvXXShFcdPRkTOWQfbtDNpNGIhtPwxKXCbmdq(STcEzAjmTjkPL,HBCxDRqHLKgLVK){ return MMoyzsy[DjvIWTHc[sWzjF(STc" ascii
    $s17 = "function h(wgmeZBtLXaibav,ooVgUqeWPPDNL,wAvJaNpGnWq) {wgmeZBtLXaibav[ooVgUqeWPPDNL]=wAvJaNpGnWq;}" fullword ascii
    $s18 = "function xPgwJPtFyAqUiqHzi(hIfZyaihdo,jRmMoLHqtm) {return parseInt(hIfZyaihdo,jRmMoLHqtm);}" fullword ascii
    $s19 = "Z);return EruWx;}" fullword ascii
    $s20 = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6a44 and
    8 of them
}