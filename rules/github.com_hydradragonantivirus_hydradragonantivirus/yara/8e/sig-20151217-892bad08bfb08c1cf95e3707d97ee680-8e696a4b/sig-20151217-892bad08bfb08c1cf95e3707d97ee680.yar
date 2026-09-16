rule sig_20151217_892bad08bfb08c1cf95e3707d97ee680 {
  meta:
    description = "datamaliciousorder - file 20151217_892bad08bfb08c1cf95e3707d97ee680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4528bba4f20573f6c4d1d2bea9003600a8b2a0c61db01bcb9bfca341548d20"

  strings:
    $s1  = "Math.cos(600), 2) - 1)));} eAAwUXftc[RXLzFoheNtD]++;}RXLzFoheNtD++;} return QSbNjZumMqI}" fullword ascii
    $s2  = "th.pow(Math.cos(345), 2) - 1)); while(true) { if(eAAwUXftc[RXLzFoheNtD] > DwjtL[RXLzFoheNtD].length-(638+292)/930) { break; } if" ascii
    $s3  = "function flImGuYzTohISePRl(DwjtL){QSbNjZumMqI= '';RXLzFoheNtD=Math.round((Math.pow(Math.sin(203), 2) + Math.pow(Math.cos(203), 2" ascii
    $s4  = ") - 1));while(true){if (RXLzFoheNtD >= (2558+970)/588){break;}eAAwUXftc[RXLzFoheNtD]=Math.round((Math.pow(Math.sin(345), 2) + Ma" ascii
    $s5  = "function flImGuYzTohISePRl(DwjtL){QSbNjZumMqI= '';RXLzFoheNtD=Math.round((Math.pow(Math.sin(203), 2) + Math.pow(Math.cos(203), 2" ascii
    $s6  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s7  = "function PTKNC(iEOiEQaThWr,xLGeUAdCQnhSj,ghPEYbWa){rfOP=otoctLDVUkBGVRJYy(iEOiEQaThWr,xLGeUAdCQnhSj);fYhdT=rfOP.toString(ghPEYbW" ascii
    $s8  = "a);return fYhdT;}" fullword ascii
    $s9  = "function otoctLDVUkBGVRJYy(iGBjElFcJp,oTsUjjlrbZ) {return parseInt(iGBjElFcJp,oTsUjjlrbZ);}" fullword ascii
    $s10 = "function qdRIfEISaQe(fEYDNDazGAQXlf) {return isNaN(fEYDNDazGAQXlf);}" fullword ascii
    $s11 = "function l(sgwMqPmxRqCS,KtsdzEfNBBMnVm){sgwMqPmxRqCS.push(KtsdzEfNBBMnVm);}" fullword ascii
    $s12 = ",'f','V',')','(','s','3','W','s','{','_','i','Z','+','X','Y','O','I','/','d','Z','z','>','J','K','k','1','_','w','[','.',String." ascii
    $s13 = "function eotCJjgLxQiZQlSVnaWqUeJVThYRrNRehflcdNFGMccEhPAICVwaHG(PPMtnuEfnlsHO,jALFosXOjjXJOB){ return PRmsAtU[wpKebuYa[PTKNC(PPM" ascii
    $s14 = "function prvGfiGMcvmjHLY(WYdAYAUUjTcHSLwAi,IIXxEmmTvmLKQrJbtqKexlueGvJxqxTsWc,AOYNDHcwvzzvtopavKNRtDuahSMaItIYshi){eval(WYdAYAUU" ascii
    $s15 = "function KfRqxjoRFLYd(nfEJYRozYHOHq) {return isFinite(nfEJYRozYHOHq);}" fullword ascii
    $s16 = "function O(SrtSsIvDgwEqIj,OmVRDOxDfmsAD,FkxQjubGjfp) {SrtSsIvDgwEqIj[OmVRDOxDfmsAD]=FkxQjubGjfp;}" fullword ascii
    $s17 = "function PTKNC(iEOiEQaThWr,xLGeUAdCQnhSj,ghPEYbWa){rfOP=otoctLDVUkBGVRJYy(iEOiEQaThWr,xLGeUAdCQnhSj);fYhdT=rfOP.toString(ghPEYbW" ascii
    $s18 = "function eotCJjgLxQiZQlSVnaWqUeJVThYRrNRehflcdNFGMccEhPAICVwaHG(PPMtnuEfnlsHO,jALFosXOjjXJOB){ return PRmsAtU[wpKebuYa[PTKNC(PPM" ascii
    $s19 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s20 = "function prvGfiGMcvmjHLY(WYdAYAUUjTcHSLwAi,IIXxEmmTvmLKQrJbtqKexlueGvJxqxTsWc,AOYNDHcwvzzvtopavKNRtDuahSMaItIYshi){eval(WYdAYAUU" ascii

  condition:
    uint16(0) == 0x7077 and
    8 of them
}