rule sig_20151217_06a58c778980f73078c3f91186c495cc {
  meta:
    description = "datamaliciousorder - file 20151217_06a58c778980f73078c3f91186c495cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e4dbde561868341995fce75c6681625a6f812e7cfeda7cef0d85f15b206594f"

  strings:
    $s1  = "function RMoGBNLlmQutTLqYp(HgErL){SfSqtnVYEGL= '';lPIMBtCTKin=Math.round((Math.pow(Math.sin(948), 2) + Math.pow(Math.cos(948), 2" ascii
    $s2  = ") - 1));while(true){if (lPIMBtCTKin >= (-291+831)/90){break;}zcyQVAcuD[lPIMBtCTKin]=Math.round((Math.pow(Math.sin(826), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(826), 2) - 1)); while(true) { if(zcyQVAcuD[lPIMBtCTKin] > HgErL[lPIMBtCTKin].length-(434+116)/550) { break; } if " ascii
    $s4  = "ow(Math.cos(371), 2) - 1)));} zcyQVAcuD[lPIMBtCTKin]++;}lPIMBtCTKin++;} return SfSqtnVYEGL}" fullword ascii
    $s5  = "function RMoGBNLlmQutTLqYp(HgErL){SfSqtnVYEGL= '';lPIMBtCTKin=Math.round((Math.pow(Math.sin(948), 2) + Math.pow(Math.cos(948), 2" ascii
    $s6  = "function GtxLMbc(BxAnaZeBuegQPxJGXeRSfiLdHcNxRhjxiJxV) {return !RMdNwohtTbG(rFnutubVSapcBwH(BxAnaZeBuegQPxJGXeRSfiLdHcNxRhjxiJxV" ascii
    $s7  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s8  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s9  = "function zHFCnXRnLmAQPcgXe(nUWfkhNQuN,AYoocrhOMN) {return parseInt(nUWfkhNQuN,AYoocrhOMN);}" fullword ascii
    $s10 = "function RMdNwohtTbG(tdgGLxsgVXHRfh) {return isNaN(tdgGLxsgVXHRfh);}" fullword ascii
    $s11 = "function vsnBd(lJUdEaDiTOF,SIfOBzyyyURiC,DJQOCUkD){sdUY=zHFCnXRnLmAQPcgXe(lJUdEaDiTOF,SIfOBzyyyURiC);ycCtc=sdUY.toString(DJQOCUk" ascii
    $s12 = "function t(lrDhvEFjxkEHlJ,UdZrygreNZvyX,rQDaJYoYCeg) {lrDhvEFjxkEHlJ[UdZrygreNZvyX]=rQDaJYoYCeg;}" fullword ascii
    $s13 = "function ffCUlvCOCUPX(gEbRyxsxsnNMr) {return isFinite(gEbRyxsxsnNMr);}" fullword ascii
    $s14 = "function GtxLMbc(BxAnaZeBuegQPxJGXeRSfiLdHcNxRhjxiJxV) {return !RMdNwohtTbG(rFnutubVSapcBwH(BxAnaZeBuegQPxJGXeRSfiLdHcNxRhjxiJxV" ascii
    $s15 = "function PQeyUtTNssYnMkf(voalcvWDpZbCZJIbR,adwhvxHcvIvgAuqbTnDmSCscgWJzTiGqTa,zfrgfumaXqbUoHYdfjsMJJTnEBnBjYRrKMp){eval(voalcvWD" ascii
    $s16 = "function vsnBd(lJUdEaDiTOF,SIfOBzyyyURiC,DJQOCUkD){sdUY=zHFCnXRnLmAQPcgXe(lJUdEaDiTOF,SIfOBzyyyURiC);ycCtc=sdUY.toString(DJQOCUk" ascii
    $s17 = "function O(lhecyiimmdDJ,TspTaxYsHnHZVY){lhecyiimmdDJ.push(TspTaxYsHnHZVY);}" fullword ascii
    $s18 = "function PQeyUtTNssYnMkf(voalcvWDpZbCZJIbR,adwhvxHcvIvgAuqbTnDmSCscgWJzTiGqTa,zfrgfumaXqbUoHYdfjsMJJTnEBnBjYRrKMp){eval(voalcvWD" ascii
    $s19 = "D);return ycCtc;}" fullword ascii
    $s20 = "function ReepgxjXfLCKdGMggCJmosdhlurnffoOjormRLKTuWPzIBcuYDfWBp(NsoPaQKljQWQY,HVrTxkOPWkJRea){ return fDtcSRY[KrOFYcfq[vsnBd(Nso" ascii

  condition:
    uint16(0) == 0x724b and
    8 of them
}