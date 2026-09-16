rule sig_20151217_32c476b1459e72d0dc591510e4ccceb8 {
  meta:
    description = "datamaliciousorder - file 20151217_32c476b1459e72d0dc591510e4ccceb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b758fc5c577145172b1b65e6b507a17244b91ef3414c656f7b65fc6935ebc385"

  strings:
    $s1  = ") - 1));while(true){if (cKoorhMczIi >= (2169+333)/417){break;}TDBcQZtzS[cKoorhMczIi]=Math.round((Math.pow(Math.sin(74), 2) + Mat" ascii
    $s2  = "function QGlUiosihkEVhEkoS(WUdsc){YjMOgeFpWcV= '';cKoorhMczIi=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.cos(610), 2" ascii
    $s3  = "w(Math.cos(246), 2) - 1)));} TDBcQZtzS[cKoorhMczIi]++;}cKoorhMczIi++;} return YjMOgeFpWcV}" fullword ascii
    $s4  = "h.pow(Math.cos(74), 2) - 1)); while(true) { if(TDBcQZtzS[cKoorhMczIi] > WUdsc[cKoorhMczIi].length-(144+813)/957) { break; } if (" ascii
    $s5  = "function QGlUiosihkEVhEkoS(WUdsc){YjMOgeFpWcV= '';cKoorhMczIi=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.cos(610), 2" ascii
    $s6  = "function FXzlhnG(lbSQmspukwMISDnTmIpHcHPVsJNSJzqrolpd) {return !rgBfBadgymr(kyZZiZIAgswXyhB(lbSQmspukwMISDnTmIpHcHPVsJNSJzqrolpd" ascii
    $s7  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s8  = "function e(yLdEHiPiIjQsKB,CvdppRFSoAnKJ,vgiCyLLNraP) {yLdEHiPiIjQsKB[CvdppRFSoAnKJ]=vgiCyLLNraP;}" fullword ascii
    $s9  = "function XJXWhpGXzbGj(UYIeTlVKchHbg) {return isFinite(UYIeTlVKchHbg);}" fullword ascii
    $s10 = "function cqkyXgtMElsSEyvTPCTGTqgZyKYFJQIaDBXYxppuRkrIuIJOybLarp(TnWrGwVelHGQb,lIXkqagpzMQKEp){ return rOOjYYB[LBpRkcun[FlvVl(TnW" ascii
    $s11 = "function FlvVl(yEpYuMepUmb,qXseinSWgjvgF,LLocecsI){wvfG=GOXedOZRNweGciTcX(yEpYuMepUmb,qXseinSWgjvgF);sWVTh=wvfG.toString(LLocecs" ascii
    $s12 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s13 = "function rgBfBadgymr(zpYjoQftitonOw) {return isNaN(zpYjoQftitonOw);}" fullword ascii
    $s14 = "function GOXedOZRNweGciTcX(kCQnoHjiBQ,DohjJocvPj) {return parseInt(kCQnoHjiBQ,DohjJocvPj);}" fullword ascii
    $s15 = "I);return sWVTh;}" fullword ascii
    $s16 = "function FlvVl(yEpYuMepUmb,qXseinSWgjvgF,LLocecsI){wvfG=GOXedOZRNweGciTcX(yEpYuMepUmb,qXseinSWgjvgF);sWVTh=wvfG.toString(LLocecs" ascii
    $s17 = "function cqkyXgtMElsSEyvTPCTGTqgZyKYFJQIaDBXYxppuRkrIuIJOybLarp(TnWrGwVelHGQb,lIXkqagpzMQKEp){ return rOOjYYB[LBpRkcun[FlvVl(TnW" ascii
    $s18 = "function FXzlhnG(lbSQmspukwMISDnTmIpHcHPVsJNSJzqrolpd) {return !rgBfBadgymr(kyZZiZIAgswXyhB(lbSQmspukwMISDnTmIpHcHPVsJNSJzqrolpd" ascii
    $s19 = "function kyZZiZIAgswXyhB(sDIwbwirtaGykTlszrK) {return parseFloat(sDIwbwirtaGykTlszrK);}" fullword ascii
    $s20 = "function I(xdETnMlJFfiP,dOBelEVhKkropR){xdETnMlJFfiP.push(dOBelEVhKkropR);}" fullword ascii

  condition:
    uint16(0) == 0x424c and
    8 of them
}