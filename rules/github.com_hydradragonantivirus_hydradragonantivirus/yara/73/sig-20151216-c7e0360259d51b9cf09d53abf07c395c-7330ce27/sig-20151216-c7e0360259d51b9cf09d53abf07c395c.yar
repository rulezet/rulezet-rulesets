rule sig_20151216_c7e0360259d51b9cf09d53abf07c395c {
  meta:
    description = "datamaliciousorder - file 20151216_c7e0360259d51b9cf09d53abf07c395c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da60a11dd1964b2fb92ea13c01aa974a6b0fa15e79135886cb800c852b9eb61c"

  strings:
    $s1  = "function bsaPDqiSNwcCpNCqP(BGRMO){WjNtjueZRaJ= '';ZeyJXsnCQrd=Math.round((Math.pow(Math.sin(127), 2) + Math.pow(Math.cos(127), 2" ascii
    $s2  = "th.pow(Math.cos(293), 2) - 1)); while(true) { if(cZzxWIWHM[ZeyJXsnCQrd] > BGRMO[ZeyJXsnCQrd].length-(325+371)/696) { break; } if" ascii
    $s3  = ") - 1));while(true){if (ZeyJXsnCQrd >= (4381+419)/800){break;}cZzxWIWHM[ZeyJXsnCQrd]=Math.round((Math.pow(Math.sin(293), 2) + Ma" ascii
    $s4  = "pow(Math.cos(945), 2) - 1)));} cZzxWIWHM[ZeyJXsnCQrd]++;}ZeyJXsnCQrd++;} return WjNtjueZRaJ}" fullword ascii
    $s5  = "acRGosKtbwgyIqFwMFHDropYcNYxNjYZVbs([BGRMO[ZeyJXsnCQrd][cZzxWIWHM[ZeyJXsnCQrd]]], Math.round((Math.pow(Math.sin(945), 2) + Math." ascii
    $s6  = "function bsaPDqiSNwcCpNCqP(BGRMO){WjNtjueZRaJ= '';ZeyJXsnCQrd=Math.round((Math.pow(Math.sin(127), 2) + Math.pow(Math.cos(127), 2" ascii
    $s7  = "function eHfzhGQ(lCjRbPjFlxlLfZoQyXVHluJjiXcKUTXOjXwb) {return !aKzcCqodNgE(YLDBjsCwxkQtoDQ(lCjRbPjFlxlLfZoQyXVHluJjiXcKUTXOjXwb" ascii
    $s8  = "function wVCGeWqvnOXekfdhfHZacRGosKtbwgyIqFwMFHDropYcNYxNjYZVbs(biBloJMbcQmCV,DQwzlNpSJrrwFm){ return LaNGZCr[KDWRCFqQ[CCvkI(biB" ascii
    $s9  = "function wVCGeWqvnOXekfdhfHZacRGosKtbwgyIqFwMFHDropYcNYxNjYZVbs(biBloJMbcQmCV,DQwzlNpSJrrwFm){ return LaNGZCr[KDWRCFqQ[CCvkI(biB" ascii
    $s10 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s11 = "function aKzcCqodNgE(dwSuFfDvmIWlFz) {return isNaN(dwSuFfDvmIWlFz);}" fullword ascii
    $s12 = "S);return DAGDP;}" fullword ascii
    $s13 = "function GAncNsdgcUpR(twYpsrywAhasV) {return isFinite(twYpsrywAhasV);}" fullword ascii
    $s14 = "function ZIRDcOPkPOUKujP(NssdRMjNeBEmvYIqY,OCraqPLgspsedNekXZZXEjheyVnqrCuVjj,tWcEmwULXeVBHPWhjpDkodHMCUBurHhqDCc){eval(NssdRMjN" ascii
    $s15 = "function zlavwzslEdOguhrSH(qsjwaPcwjx,qoMMlEJjqs) {return parseInt(qsjwaPcwjx,qoMMlEJjqs);}" fullword ascii
    $s16 = "function P(xnKyBpizypbb,uqUMHkXQJwkBEe){xnKyBpizypbb.push(uqUMHkXQJwkBEe);}" fullword ascii
    $s17 = "function CCvkI(UvWRixEdyjq,ykasFqRiodEqJ,mjhUUirS){pxFP=zlavwzslEdOguhrSH(UvWRixEdyjq,ykasFqRiodEqJ);DAGDP=pxFP.toString(mjhUUir" ascii
    $s18 = "function l(hSNMySgZHuXCIr,KIIEZGPZMGzCO,wMGGIoRXzkB) {hSNMySgZHuXCIr[KIIEZGPZMGzCO]=wMGGIoRXzkB;}" fullword ascii
    $s19 = "function YLDBjsCwxkQtoDQ(vxIHOMugWlalrArTVJi) {return parseFloat(vxIHOMugWlalrArTVJi);}" fullword ascii
    $s20 = "function CCvkI(UvWRixEdyjq,ykasFqRiodEqJ,mjhUUirS){pxFP=zlavwzslEdOguhrSH(UvWRixEdyjq,ykasFqRiodEqJ);DAGDP=pxFP.toString(mjhUUir" ascii

  condition:
    uint16(0) == 0x444b and
    8 of them
}