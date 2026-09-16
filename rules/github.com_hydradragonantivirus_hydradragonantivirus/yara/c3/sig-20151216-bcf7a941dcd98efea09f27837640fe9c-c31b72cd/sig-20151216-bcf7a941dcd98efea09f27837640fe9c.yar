rule sig_20151216_bcf7a941dcd98efea09f27837640fe9c {
  meta:
    description = "datamaliciousorder - file 20151216_bcf7a941dcd98efea09f27837640fe9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a93a35d04004a69f95f206c7727de344c2d71774632f64de50c26c4aad10330d"

  strings:
    $s1  = "Math.cos(862), 2) - 1)));} PCKnZBKsI[RzzMwDShtDI]++;}RzzMwDShtDI++;} return hhFMbMQguhm}" fullword ascii
    $s2  = "function HKiDApPKGDJvDWpQq(qQbeL){hhFMbMQguhm= '';RzzMwDShtDI=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s3  = "pow(Math.cos(96), 2) - 1)); while(true) { if(PCKnZBKsI[RzzMwDShtDI] > qQbeL[RzzMwDShtDI].length-(-134+871)/737) { break; } if (J" ascii
    $s4  = "function HKiDApPKGDJvDWpQq(qQbeL){hhFMbMQguhm= '';RzzMwDShtDI=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s5  = "- 1));while(true){if (RzzMwDShtDI >= (-165+999)/139){break;}PCKnZBKsI[RzzMwDShtDI]=Math.round((Math.pow(Math.sin(96), 2) + Math." ascii
    $s6  = "function DvPgthpelgiZZHqnCMwwKFGLmujYEIszDwLaGtVhWjAUrwkIQBdIDS(XOLAuThqwqsXt,auZNYIUqnbruHR){ return IpVbveD[YzcYpAss[ZLbSp(XOL" ascii
    $s7  = "function DvPgthpelgiZZHqnCMwwKFGLmujYEIszDwLaGtVhWjAUrwkIQBdIDS(XOLAuThqwqsXt,auZNYIUqnbruHR){ return IpVbveD[YzcYpAss[ZLbSp(XOL" ascii
    $s8  = "function JtjHyEo(LZtMiUqZKbRSPlHJBdJXlfKPjvBFPFJkYaeB) {return !IANaQXaphSh(qLcyVnwJTVZNAnH(LZtMiUqZKbRSPlHJBdJXlfKPjvBFPFJkYaeB" ascii
    $s9  = "function bwjeftAqOxSn(nhxzsHIPafBGi) {return isFinite(nhxzsHIPafBGi);}" fullword ascii
    $s10 = "a);return tDiEj;}" fullword ascii
    $s11 = "function kZPDjoaLqVwasBi(qQgYmYNkqUvfbBAPg,OuDAnKYixdsHZVuenPLONUyDLppmLVdvjw,HqUdXAPttHXFsxRNzcYpQZJNnrIHVnPzbxK){eval(qQgYmYNk" ascii
    $s12 = "function gkRTqtsDNNyYIjWGs(rzyofFNNfr,UmfiiiFaAS) {return parseInt(rzyofFNNfr,UmfiiiFaAS);}" fullword ascii
    $s13 = "function G(gipcxDsyMxkjVj,RXmKXoCkbNLMg,lSjwxkliaik) {gipcxDsyMxkjVj[RXmKXoCkbNLMg]=lSjwxkliaik;}" fullword ascii
    $s14 = "function IANaQXaphSh(lYVeahwVFKEHQb) {return isNaN(lYVeahwVFKEHQb);}" fullword ascii
    $s15 = "function ZLbSp(TZwpYJyDHeY,fOcJCtKuaVUIl,bRSjmhfa){UXAQ=gkRTqtsDNNyYIjWGs(TZwpYJyDHeY,fOcJCtKuaVUIl);tDiEj=UXAQ.toString(bRSjmhf" ascii
    $s16 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s17 = "function kZPDjoaLqVwasBi(qQgYmYNkqUvfbBAPg,OuDAnKYixdsHZVuenPLONUyDLppmLVdvjw,HqUdXAPttHXFsxRNzcYpQZJNnrIHVnPzbxK){eval(qQgYmYNk" ascii
    $s18 = "function v(tehboSulPyVq,EhIioyXpzgGhIB){tehboSulPyVq.push(EhIioyXpzgGhIB);}" fullword ascii
    $s19 = "function ZLbSp(TZwpYJyDHeY,fOcJCtKuaVUIl,bRSjmhfa){UXAQ=gkRTqtsDNNyYIjWGs(TZwpYJyDHeY,fOcJCtKuaVUIl);tDiEj=UXAQ.toString(bRSjmhf" ascii
    $s20 = "function JtjHyEo(LZtMiUqZKbRSPlHJBdJXlfKPjvBFPFJkYaeB) {return !IANaQXaphSh(qLcyVnwJTVZNAnH(LZtMiUqZKbRSPlHJBdJXlfKPjvBFPFJkYaeB" ascii

  condition:
    uint16(0) == 0x7a59 and
    8 of them
}