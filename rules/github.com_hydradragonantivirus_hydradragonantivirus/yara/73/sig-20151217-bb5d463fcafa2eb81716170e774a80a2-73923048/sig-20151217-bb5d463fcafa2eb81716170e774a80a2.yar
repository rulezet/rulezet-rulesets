rule sig_20151217_bb5d463fcafa2eb81716170e774a80a2 {
  meta:
    description = "datamaliciousorder - file 20151217_bb5d463fcafa2eb81716170e774a80a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f93dfc14df294f7bb4205f62a53726feddcde31b49383c19284a69d4a01a2602"

  strings:
    $s1  = "function xYfkUkXeuJshdCroy(nBKxB){uTwSheDyUJo= '';eykKyemgEVr=Math.round((Math.pow(Math.sin(415), 2) + Math.pow(Math.cos(415), 2" ascii
    $s2  = "h.pow(Math.cos(15), 2) - 1)); while(true) { if(NHSDAGQRQ[eykKyemgEVr] > nBKxB[eykKyemgEVr].length-(821+29)/850) { break; } if (N" ascii
    $s3  = "(Math.cos(681), 2) - 1)));} NHSDAGQRQ[eykKyemgEVr]++;}eykKyemgEVr++;} return uTwSheDyUJo}" fullword ascii
    $s4  = ") - 1));while(true){if (eykKyemgEVr >= (5371+251)/937){break;}NHSDAGQRQ[eykKyemgEVr]=Math.round((Math.pow(Math.sin(15), 2) + Mat" ascii
    $s5  = "function xYfkUkXeuJshdCroy(nBKxB){uTwSheDyUJo= '';eykKyemgEVr=Math.round((Math.pow(Math.sin(415), 2) + Math.pow(Math.cos(415), 2" ascii
    $s6  = "function NOKqjZf(JzlohIrQAkkEsLhrJKqfvvVYGfjLqiwUDLZS) {return !OojLubQuZBc(qPtZsXSaJrgafDH(JzlohIrQAkkEsLhrJKqfvvVYGfjLqiwUDLZS" ascii
    $s7  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s8  = "function gvnYl(ypdtKNEOfMx,gHRhQoIVQPDMw,QhinDGbp){nJpO=qZqoupogcqjassjgX(ypdtKNEOfMx,gHRhQoIVQPDMw);TibzJ=nJpO.toString(QhinDGb" ascii
    $s9  = "function qPtZsXSaJrgafDH(DDCwlRkMoXpcPRFFgKr) {return parseFloat(DDCwlRkMoXpcPRFFgKr);}" fullword ascii
    $s10 = "function gvnYl(ypdtKNEOfMx,gHRhQoIVQPDMw,QhinDGbp){nJpO=qZqoupogcqjassjgX(ypdtKNEOfMx,gHRhQoIVQPDMw);TibzJ=nJpO.toString(QhinDGb" ascii
    $s11 = "function XZTSDLWdZZek(osNVvJvgzIzDr) {return isFinite(osNVvJvgzIzDr);}" fullword ascii
    $s12 = "function wlitysmUgBrSRlPLygFBrXyAUihzNpOqmVrNWhYnShXSvimDPFuply(uWnFeLaLRdcRM,zzrOzQGsXZaWHk){ return LIPugVW[fGFSpcMb[gvnYl(uWn" ascii
    $s13 = "function OojLubQuZBc(ljZJxuSZVYwPdR) {return isNaN(ljZJxuSZVYwPdR);}" fullword ascii
    $s14 = "function NOKqjZf(JzlohIrQAkkEsLhrJKqfvvVYGfjLqiwUDLZS) {return !OojLubQuZBc(qPtZsXSaJrgafDH(JzlohIrQAkkEsLhrJKqfvvVYGfjLqiwUDLZS" ascii
    $s15 = "function wlitysmUgBrSRlPLygFBrXyAUihzNpOqmVrNWhYnShXSvimDPFuply(uWnFeLaLRdcRM,zzrOzQGsXZaWHk){ return LIPugVW[fGFSpcMb[gvnYl(uWn" ascii
    $s16 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s17 = "p);return TibzJ;}" fullword ascii
    $s18 = "function QBcLnJIsAhkJJGM(vpUvOuiYehsZOMRKN,fIHgltgbBMelPENmmeXkYBeOZrcWooeAdH,gTeJNigjQJvAcWovcgRfcIYLzaodrLrZmbQ){eval(vpUvOuiY" ascii
    $s19 = "function J(uvIvZbjJdzpp,khWgqmqhNLQyiT){uvIvZbjJdzpp.push(khWgqmqhNLQyiT);}" fullword ascii
    $s20 = "function qZqoupogcqjassjgX(WCoJMdaRPY,hbfEMovxfR) {return parseInt(WCoJMdaRPY,hbfEMovxfR);}" fullword ascii

  condition:
    uint16(0) == 0x4766 and
    8 of them
}