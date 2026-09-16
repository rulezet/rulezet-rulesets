rule sig_20151217_8d66fd96a720cb973f4508d21ac09fbf {
  meta:
    description = "datamaliciousorder - file 20151217_8d66fd96a720cb973f4508d21ac09fbf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9db5ca3f6e66272752874021dda84cc79c693e6e31049d6b597a850455a803"

  strings:
    $s1  = "Math.cos(525), 2) - 1)));} szNXnUxtI[ZmehFAWzliw]++;}ZmehFAWzliw++;} return fkyAStoaUBE}" fullword ascii
    $s2  = ") - 1));while(true){if (ZmehFAWzliw >= (1505+631)/356){break;}szNXnUxtI[ZmehFAWzliw]=Math.round((Math.pow(Math.sin(706), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(706), 2) - 1)); while(true) { if(szNXnUxtI[ZmehFAWzliw] > NdrAY[ZmehFAWzliw].length-(-94+778)/684) { break; } if" ascii
    $s4  = "function YwsOqVMFBarkWAcrd(NdrAY){fkyAStoaUBE= '';ZmehFAWzliw=Math.round((Math.pow(Math.sin(270), 2) + Math.pow(Math.cos(270), 2" ascii
    $s5  = "function YwsOqVMFBarkWAcrd(NdrAY){fkyAStoaUBE= '';ZmehFAWzliw=Math.round((Math.pow(Math.sin(270), 2) + Math.pow(Math.cos(270), 2" ascii
    $s6  = "function keWRFha(poJxQPLOaEUVjmlXXpdsBNoezOrRQFzJclhH) {return !YQXwoYUPIEr(mfsSRLGimJKwxwr(poJxQPLOaEUVjmlXXpdsBNoezOrRQFzJclhH" ascii
    $s7  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s8  = "function lyQgHtHTCdazKDbQLsfNynfyyvSxmHEMptaZxBwCwymjTwvCTiSeWf(tqrSJcnRdEUOQ,SuNcTAVqgNKPOG){ return urlQycg[HxWbpBNh[eWaNx(tqr" ascii
    $s9  = "function U(ZkBBDWhJmECj,qBHHOcfuANoYSm){ZkBBDWhJmECj.push(qBHHOcfuANoYSm);}" fullword ascii
    $s10 = "function IWiQHgmRLuFwNVW(SLmWAMKQLZzyEhmyT,sdxGLZvxEeaDIARVoKHggiDrBDcQUxYLrN,uzXbHxEbUcoXdcuoiHNmYrmPDqBBmOifJet){eval(SLmWAMKQ" ascii
    $s11 = "function YQXwoYUPIEr(hOuwrdrcNgzUDB) {return isNaN(hOuwrdrcNgzUDB);}" fullword ascii
    $s12 = "function mfsSRLGimJKwxwr(vmIMbizyebRAhRtAHhu) {return parseFloat(vmIMbizyebRAhRtAHhu);}" fullword ascii
    $s13 = "function eWaNx(leeiylmZgwi,zMOgwdWKmFtLm,WLpJJryI){TUPn=QDLXYjOPIdsvHjBmN(leeiylmZgwi,zMOgwdWKmFtLm);GVHPP=TUPn.toString(WLpJJry" ascii
    $s14 = "function lyQgHtHTCdazKDbQLsfNynfyyvSxmHEMptaZxBwCwymjTwvCTiSeWf(tqrSJcnRdEUOQ,SuNcTAVqgNKPOG){ return urlQycg[HxWbpBNh[eWaNx(tqr" ascii
    $s15 = "function QDLXYjOPIdsvHjBmN(luweKisInL,xdSMOlYGlH) {return parseInt(luweKisInL,xdSMOlYGlH);}" fullword ascii
    $s16 = "function NYlQzAHquZPA(hpZEUqWkXEBhY) {return isFinite(hpZEUqWkXEBhY);}" fullword ascii
    $s17 = "function D(YpOdRrHYaDtATG,lxamAxHuzCZIE,vFjZGZnwCvV) {YpOdRrHYaDtATG[lxamAxHuzCZIE]=vFjZGZnwCvV;}" fullword ascii
    $s18 = "function IWiQHgmRLuFwNVW(SLmWAMKQLZzyEhmyT,sdxGLZvxEeaDIARVoKHggiDrBDcQUxYLrN,uzXbHxEbUcoXdcuoiHNmYrmPDqBBmOifJet){eval(SLmWAMKQ" ascii
    $s19 = "I);return GVHPP;}" fullword ascii
    $s20 = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii

  condition:
    uint16(0) == 0x7848 and
    8 of them
}