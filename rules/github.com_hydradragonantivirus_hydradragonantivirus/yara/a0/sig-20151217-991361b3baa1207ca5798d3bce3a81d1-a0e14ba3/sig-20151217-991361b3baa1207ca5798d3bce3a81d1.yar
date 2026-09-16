rule sig_20151217_991361b3baa1207ca5798d3bce3a81d1 {
  meta:
    description = "datamaliciousorder - file 20151217_991361b3baa1207ca5798d3bce3a81d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b26d40dd2a6da7ccbdd24494b3807d1b91bde28eca4f6e51c7aeb26e91cad2c"

  strings:
    $s1  = "th.pow(Math.cos(921), 2) - 1)); while(true) { if(kMKvxVJkm[jMJMjPVCLJC] > cMfZc[jMJMjPVCLJC].length-(473+412)/885) { break; } if" ascii
    $s2  = "function BZZzsINujVWUyQriH(cMfZc){gJgKmXGWjnN= '';jMJMjPVCLJC=Math.round((Math.pow(Math.sin(171), 2) + Math.pow(Math.cos(171), 2" ascii
    $s3  = "ow(Math.cos(478), 2) - 1)));} kMKvxVJkm[jMJMjPVCLJC]++;}jMJMjPVCLJC++;} return gJgKmXGWjnN}" fullword ascii
    $s4  = ") - 1));while(true){if (jMJMjPVCLJC >= (1100+364)/244){break;}kMKvxVJkm[jMJMjPVCLJC]=Math.round((Math.pow(Math.sin(921), 2) + Ma" ascii
    $s5  = "function BZZzsINujVWUyQriH(cMfZc){gJgKmXGWjnN= '';jMJMjPVCLJC=Math.round((Math.pow(Math.sin(171), 2) + Math.pow(Math.cos(171), 2" ascii
    $s6  = "function cnBCybU(UdEOjsJNuFPaBZLghrxSaZAzhfXuLqqickgQ) {return !oErlCOWiIbu(sLcEAlqQPVAbvGj(UdEOjsJNuFPaBZLghrxSaZAzhfXuLqqickgQ" ascii
    $s7  = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s8  = "function cnBCybU(UdEOjsJNuFPaBZLghrxSaZAzhfXuLqqickgQ) {return !oErlCOWiIbu(sLcEAlqQPVAbvGj(UdEOjsJNuFPaBZLghrxSaZAzhfXuLqqickgQ" ascii
    $s9  = "function H(oJtgnGaIROLxgW,oiVhuwtwKIADe,ajAIGfGOSBx) {oJtgnGaIROLxgW[oiVhuwtwKIADe]=ajAIGfGOSBx;}" fullword ascii
    $s10 = "function oErlCOWiIbu(OEfxauFYuVVpdx) {return isNaN(OEfxauFYuVVpdx);}" fullword ascii
    $s11 = "function zZiUqhACJFMgwHrBHaPbDAseXRTxUKAvYADOOdgsnrDRvLaIvPNdAb(ybnQAZNdiDpFG,QFbPciXXzQZoSr){ return MGdeits[AWPFTxRc[iZyqV(ybn" ascii
    $s12 = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s13 = "G);return IOMoI;}" fullword ascii
    $s14 = "function iZyqV(uOrhwxEsOES,cZbUgxcjpmSTN,riaKAyWG){dvfk=wFymmpdjmzKJtUqFI(uOrhwxEsOES,cZbUgxcjpmSTN);IOMoI=dvfk.toString(riaKAyW" ascii
    $s15 = "function zZiUqhACJFMgwHrBHaPbDAseXRTxUKAvYADOOdgsnrDRvLaIvPNdAb(ybnQAZNdiDpFG,QFbPciXXzQZoSr){ return MGdeits[AWPFTxRc[iZyqV(ybn" ascii
    $s16 = "function fkspdACxFLAe(XrdLhJTAabDoG) {return isFinite(XrdLhJTAabDoG);}" fullword ascii
    $s17 = "function LqXLHwNAPZicUfj(YMSZMLFNCzSPoJkVo,qqfGjcDLVFhBNVEnVEEAOBMEpehLSxEnGC,tbPYdTzqWiyVrBrEwfqmfUHGkLTQVMLOABi){eval(YMSZMLFN" ascii
    $s18 = "function wFymmpdjmzKJtUqFI(ceGklaBmon,FyGHzHoUeP) {return parseInt(ceGklaBmon,FyGHzHoUeP);}" fullword ascii
    $s19 = "function LqXLHwNAPZicUfj(YMSZMLFNCzSPoJkVo,qqfGjcDLVFhBNVEnVEEAOBMEpehLSxEnGC,tbPYdTzqWiyVrBrEwfqmfUHGkLTQVMLOABi){eval(YMSZMLFN" ascii
    $s20 = "function iZyqV(uOrhwxEsOES,cZbUgxcjpmSTN,riaKAyWG){dvfk=wFymmpdjmzKJtUqFI(uOrhwxEsOES,cZbUgxcjpmSTN);IOMoI=dvfk.toString(riaKAyW" ascii

  condition:
    uint16(0) == 0x5741 and
    8 of them
}