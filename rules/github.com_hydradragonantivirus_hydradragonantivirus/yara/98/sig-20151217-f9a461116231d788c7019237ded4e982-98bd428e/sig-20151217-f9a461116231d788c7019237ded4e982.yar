rule sig_20151217_f9a461116231d788c7019237ded4e982 {
  meta:
    description = "datamaliciousorder - file 20151217_f9a461116231d788c7019237ded4e982.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4414c4d89de8a6964b28edc67e7d772e9dc5b974f692ccac36530c22d1fe2397"

  strings:
    $s1  = "th.pow(Math.cos(673), 2) - 1)); while(true) { if(RsNmyOJKG[KQxUVxgpSvR] > aKcRk[KQxUVxgpSvR].length-(-332+532)/200) { break; } i" ascii
    $s2  = ") - 1));while(true){if (KQxUVxgpSvR >= (5400+456)/976){break;}RsNmyOJKG[KQxUVxgpSvR]=Math.round((Math.pow(Math.sin(673), 2) + Ma" ascii
    $s3  = "pow(Math.cos(14), 2) - 1)));} RsNmyOJKG[KQxUVxgpSvR]++;}KQxUVxgpSvR++;} return BIiTYHUbKsP}" fullword ascii
    $s4  = "function DbDjDXhSVfBufCjQM(aKcRk){BIiTYHUbKsP= '';KQxUVxgpSvR=Math.round((Math.pow(Math.sin(506), 2) + Math.pow(Math.cos(506), 2" ascii
    $s5  = "yurNWGeqbUMMPDEzNQWFRLdbOHDEEcQsGyMD([aKcRk[KQxUVxgpSvR][RsNmyOJKG[KQxUVxgpSvR]]], Math.round((Math.pow(Math.sin(14), 2) + Math." ascii
    $s6  = "function DbDjDXhSVfBufCjQM(aKcRk){BIiTYHUbKsP= '';KQxUVxgpSvR=Math.round((Math.pow(Math.sin(506), 2) + Math.pow(Math.cos(506), 2" ascii
    $s7  = "function MznxXfx(FMNJqjeLAUyXYYLQmFQIAJiXiSwvzUwcFOdb) {return !oUvLgmiBIlN(HdNcjrsTXfPODCT(FMNJqjeLAUyXYYLQmFQIAJiXiSwvzUwcFOdb" ascii
    $s8  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s9  = "function rezkq(loEBLVUTafM,DLwxssBDODAuC,aQOKzxpz){fsVz=zGXHsHmYPHhPFpnSw(loEBLVUTafM,DLwxssBDODAuC);wFmSz=fsVz.toString(aQOKzxp" ascii
    $s10 = "function OccigRpUMVBqmmvtaCyurNWGeqbUMMPDEzNQWFRLdbOHDEEcQsGyMD(LTaHPpYSbwASu,YmSQprskhqxMrp){ return GCLYtuT[HdyjxGNC[rezkq(LTa" ascii
    $s11 = "function G(wqwcrxfBFjmkfy,TmNSaKdAXdjXy,GjoUNMpmOYN) {wqwcrxfBFjmkfy[TmNSaKdAXdjXy]=GjoUNMpmOYN;}" fullword ascii
    $s12 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s13 = "function MQplluAcuQPs(XldfbcJHldtbS) {return isFinite(XldfbcJHldtbS);}" fullword ascii
    $s14 = "function y(xoknQsbAJDUH,cVuJalGQnExvrz){xoknQsbAJDUH.push(cVuJalGQnExvrz);}" fullword ascii
    $s15 = "function zGXHsHmYPHhPFpnSw(TGrcUiYMgh,zDRdXNRVXs) {return parseInt(TGrcUiYMgh,zDRdXNRVXs);}" fullword ascii
    $s16 = ",'h','?','-','s','N','W','6','G','Q','@','X','3','k','H',',','Y','_','C','4','U','a','q','Z','[','9','d','[','^','H','5',String." ascii
    $s17 = "function OccigRpUMVBqmmvtaCyurNWGeqbUMMPDEzNQWFRLdbOHDEEcQsGyMD(LTaHPpYSbwASu,YmSQprskhqxMrp){ return GCLYtuT[HdyjxGNC[rezkq(LTa" ascii
    $s18 = "function oUvLgmiBIlN(PcdyKZwdjjeDup) {return isNaN(PcdyKZwdjjeDup);}" fullword ascii
    $s19 = "function UJQzVMdEYQmaazy(AdCrgTvmJrVfzahvH,QHILzaMVSczRZDnWuFZeziNuBHodZshqQf,OxQApqDtqZGiDoEGxJZkFKExkwAKUtOewpF){eval(AdCrgTvm" ascii
    $s20 = "function UJQzVMdEYQmaazy(AdCrgTvmJrVfzahvH,QHILzaMVSczRZDnWuFZeziNuBHodZshqQf,OxQApqDtqZGiDoEGxJZkFKExkwAKUtOewpF){eval(AdCrgTvm" ascii

  condition:
    uint16(0) == 0x6448 and
    8 of them
}