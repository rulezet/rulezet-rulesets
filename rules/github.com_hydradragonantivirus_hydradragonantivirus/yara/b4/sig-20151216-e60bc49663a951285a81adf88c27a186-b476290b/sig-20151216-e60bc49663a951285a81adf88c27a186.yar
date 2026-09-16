rule sig_20151216_e60bc49663a951285a81adf88c27a186 {
  meta:
    description = "datamaliciousorder - file 20151216_e60bc49663a951285a81adf88c27a186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e08e197125934694200041acd12e5c24e5182897ee1a3ffc80106b5499138c"

  strings:
    $s1  = "ath.pow(Math.cos(127), 2) - 1)); while(true) { if(mKNWMHCPg[vyHEjpyJUdw] > DJqGd[vyHEjpyJUdw].length-(-432+792)/360) { break; } " ascii
    $s2  = "function khRQpalcPjxYCJuRs(DJqGd){JLBcFIIbVbh= '';vyHEjpyJUdw=Math.round((Math.pow(Math.sin(1000), 2) + Math.pow(Math.cos(1000)," ascii
    $s3  = ".pow(Math.cos(460), 2) - 1)));} mKNWMHCPg[vyHEjpyJUdw]++;}vyHEjpyJUdw++;} return JLBcFIIbVbh}" fullword ascii
    $s4  = " 2) - 1));while(true){if (vyHEjpyJUdw >= (466+260)/121){break;}mKNWMHCPg[vyHEjpyJUdw]=Math.round((Math.pow(Math.sin(127), 2) + M" ascii
    $s5  = "function khRQpalcPjxYCJuRs(DJqGd){JLBcFIIbVbh= '';vyHEjpyJUdw=Math.round((Math.pow(Math.sin(1000), 2) + Math.pow(Math.cos(1000)," ascii
    $s6  = "HNZbqrIbKmkTYSDJUzocWwRNsgFwTJGeRnUX([DJqGd[vyHEjpyJUdw][mKNWMHCPg[vyHEjpyJUdw]]], Math.round((Math.pow(Math.sin(460), 2) + Math" ascii
    $s7  = "function wQvCRGm(cjlBhfXCdwtoaLkUWWNwoXQJoSFWjcfvnRRN) {return !POooDQFUVTT(kifQWzAMtOBRFkK(cjlBhfXCdwtoaLkUWWNwoXQJoSFWjcfvnRRN" ascii
    $s8  = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s9  = "function kifQWzAMtOBRFkK(cWAmZEmnfeQdzNqQiDe) {return parseFloat(cWAmZEmnfeQdzNqQiDe);}" fullword ascii
    $s10 = "function t(QheTGWURWjokXx,LhHNUNihqhSdZ,XBCpXzGnmdd) {QheTGWURWjokXx[LhHNUNihqhSdZ]=XBCpXzGnmdd;}" fullword ascii
    $s11 = "function fMkhcOqAHZttSzLirzHNZbqrIbKmkTYSDJUzocWwRNsgFwTJGeRnUX(FXCMHeBcNKEsN,QXuYALRTnjjWwo){ return VwfqJLx[qiuzhRtS[fFChU(FXC" ascii
    $s12 = "function HltoUelsvtEoEGn(SjLxubEkHLZsCvVCV,OEycnxMaaEmjhtGYtYLpFpiASGyAXblyTD,lCNEmXpITVGGRndYqXeidMGGOiTgnUNTyqj){eval(SjLxubEk" ascii
    $s13 = "z);return IZUbr;}" fullword ascii
    $s14 = "function fMkhcOqAHZttSzLirzHNZbqrIbKmkTYSDJUzocWwRNsgFwTJGeRnUX(FXCMHeBcNKEsN,QXuYALRTnjjWwo){ return VwfqJLx[qiuzhRtS[fFChU(FXC" ascii
    $s15 = "function y(DeiGBLsLVSuE,rOiZHnursGVnYK){DeiGBLsLVSuE.push(rOiZHnursGVnYK);}" fullword ascii
    $s16 = "function fFChU(gNRIihLuLhr,XMyoDyeZqFiGp,BEbkLZSz){twuU=cxeytbeslpBDHNMJc(gNRIihLuLhr,XMyoDyeZqFiGp);IZUbr=twuU.toString(BEbkLZS" ascii
    $s17 = "function cxeytbeslpBDHNMJc(wKLNWMDNDU,typfXNPPJK) {return parseInt(wKLNWMDNDU,typfXNPPJK);}" fullword ascii
    $s18 = "function HltoUelsvtEoEGn(SjLxubEkHLZsCvVCV,OEycnxMaaEmjhtGYtYLpFpiASGyAXblyTD,lCNEmXpITVGGRndYqXeidMGGOiTgnUNTyqj){eval(SjLxubEk" ascii
    $s19 = "function POooDQFUVTT(nhWBxWINfseFLr) {return isNaN(nhWBxWINfseFLr);}" fullword ascii
    $s20 = "function aloJOMjeHwbJ(WJjdskyrCFRsF) {return isFinite(WJjdskyrCFRsF);}" fullword ascii

  condition:
    uint16(0) == 0x6971 and
    8 of them
}