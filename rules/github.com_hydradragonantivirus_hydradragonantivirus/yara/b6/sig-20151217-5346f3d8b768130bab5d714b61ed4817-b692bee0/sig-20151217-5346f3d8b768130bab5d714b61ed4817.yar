rule sig_20151217_5346f3d8b768130bab5d714b61ed4817 {
  meta:
    description = "datamaliciousorder - file 20151217_5346f3d8b768130bab5d714b61ed4817.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dce932de262f79c5e10a791d0b9c6a734ca2dc94bb4c181c8ba7ef7b21d4d86"

  strings:
    $s1  = "function KfOITKPvXpMHacBRQ(kAZUW){pVRsSvNlNGK= '';MamgQcdYLex=Math.round((Math.pow(Math.sin(915), 2) + Math.pow(Math.cos(915), 2" ascii
    $s2  = ") - 1));while(true){if (MamgQcdYLex >= (5149+95)/874){break;}ysvhQcphE[MamgQcdYLex]=Math.round((Math.pow(Math.sin(549), 2) + Mat" ascii
    $s3  = "pow(Math.cos(252), 2) - 1)));} ysvhQcphE[MamgQcdYLex]++;}MamgQcdYLex++;} return pVRsSvNlNGK}" fullword ascii
    $s4  = "h.pow(Math.cos(549), 2) - 1)); while(true) { if(ysvhQcphE[MamgQcdYLex] > kAZUW[MamgQcdYLex].length-(-182+813)/631) { break; } if" ascii
    $s5  = "bECpuwpZgffrQvAlZeKyKWBPjtNpKfgyses([kAZUW[MamgQcdYLex][ysvhQcphE[MamgQcdYLex]]], Math.round((Math.pow(Math.sin(252), 2) + Math." ascii
    $s6  = "function KfOITKPvXpMHacBRQ(kAZUW){pVRsSvNlNGK= '';MamgQcdYLex=Math.round((Math.pow(Math.sin(915), 2) + Math.pow(Math.cos(915), 2" ascii
    $s7  = "function WLkmroj(hJrkimnIBHrvSOMupnMiiDcDXoLgLhujzwOn) {return !LehlMfadKJg(dtGSIqFMTREMJVi(hJrkimnIBHrvSOMupnMiiDcDXoLgLhujzwOn" ascii
    $s8  = "function tHwxZXerRWsf(xKTqVRhAmeyTN) {return isFinite(xKTqVRhAmeyTN);}" fullword ascii
    $s9  = "function dtGSIqFMTREMJVi(kWlaYmwAdkSUOYydqNg) {return parseFloat(kWlaYmwAdkSUOYydqNg);}" fullword ascii
    $s10 = "function LehlMfadKJg(vUpYvmEnEJULlL) {return isNaN(vUpYvmEnEJULlL);}" fullword ascii
    $s11 = "function NtBpZdIXIfszypu(luwvkBboTJAiJNZIx,hmuTboqieYhtdSVhofHflsfBZWVgSQcnUF,SqqwZEJTPymnRDUsiLRcRPEZMNPNoeIojJw){eval(luwvkBbo" ascii
    $s12 = "function WLkmroj(hJrkimnIBHrvSOMupnMiiDcDXoLgLhujzwOn) {return !LehlMfadKJg(dtGSIqFMTREMJVi(hJrkimnIBHrvSOMupnMiiDcDXoLgLhujzwOn" ascii
    $s13 = "function BdFLBjwLiKajTtQsIdNbECpuwpZgffrQvAlZeKyKWBPjtNpKfgyses(mRBnqYaagTIke,YosdUZOKnjQbAY){ return fKABwSF[yqpvKVPn[gCSfd(mRB" ascii
    $s14 = "g);return YZAfV;}" fullword ascii
    $s15 = "function t(KcxewMZJLsYAPE,UXwOrsZHlkYIG,LJzUDEITXuj) {KcxewMZJLsYAPE[UXwOrsZHlkYIG]=LJzUDEITXuj;}" fullword ascii
    $s16 = "function NtBpZdIXIfszypu(luwvkBboTJAiJNZIx,hmuTboqieYhtdSVhofHflsfBZWVgSQcnUF,SqqwZEJTPymnRDUsiLRcRPEZMNPNoeIojJw){eval(luwvkBbo" ascii
    $s17 = "function XJVoCzvIBFomiVLnW(bscRaULVRi,ZBhDrMgMLd) {return parseInt(bscRaULVRi,ZBhDrMgMLd);}" fullword ascii
    $s18 = "function BdFLBjwLiKajTtQsIdNbECpuwpZgffrQvAlZeKyKWBPjtNpKfgyses(mRBnqYaagTIke,YosdUZOKnjQbAY){ return fKABwSF[yqpvKVPn[gCSfd(mRB" ascii
    $s19 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s20 = "function gCSfd(dHdTvVkePUQ,aQMpkDqdyZYhn,HThgCARg){ztEf=XJVoCzvIBFomiVLnW(dHdTvVkePUQ,aQMpkDqdyZYhn);YZAfV=ztEf.toString(HThgCAR" ascii

  condition:
    uint16(0) == 0x7179 and
    8 of them
}