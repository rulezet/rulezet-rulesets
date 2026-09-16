rule sig_20151217_ebe21b9c6aba7b3cc5119b5dade6f325 {
  meta:
    description = "datamaliciousorder - file 20151217_ebe21b9c6aba7b3cc5119b5dade6f325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b4d8f59dc3cb37773ba5b55cde69b214123cce2687f404347994ef8e2edbb8d"

  strings:
    $s1  = "function CnIrlHlwTlFGRFcGz(LznDM){ZtYwUdzGDYq= '';lannZttwxdA=Math.round((Math.pow(Math.sin(974), 2) + Math.pow(Math.cos(974), 2" ascii
    $s2  = "th.pow(Math.cos(203), 2) - 1)); while(true) { if(qsjEPTyrb[lannZttwxdA] > LznDM[lannZttwxdA].length-(-383+554)/171) { break; } i" ascii
    $s3  = ") - 1));while(true){if (lannZttwxdA >= (4974+204)/863){break;}qsjEPTyrb[lannZttwxdA]=Math.round((Math.pow(Math.sin(203), 2) + Ma" ascii
    $s4  = "w(Math.cos(507), 2) - 1)));} qsjEPTyrb[lannZttwxdA]++;}lannZttwxdA++;} return ZtYwUdzGDYq}" fullword ascii
    $s5  = "function CnIrlHlwTlFGRFcGz(LznDM){ZtYwUdzGDYq= '';lannZttwxdA=Math.round((Math.pow(Math.sin(974), 2) + Math.pow(Math.cos(974), 2" ascii
    $s6  = "function phYTbDb(iqFczqYitvIniXsAbVkpCJSPRmyJtPhjeCZY) {return !gNzufHTSDzZ(xbozrcGNnzSrpLj(iqFczqYitvIniXsAbVkpCJSPRmyJtPhjeCZY" ascii
    $s7  = "function xbozrcGNnzSrpLj(FIXRFLuVeavjAqmXNNa) {return parseFloat(FIXRFLuVeavjAqmXNNa);}" fullword ascii
    $s8  = "function bwlOdaCESRRy(FWTMCIVfAxEMu) {return isFinite(FWTMCIVfAxEMu);}" fullword ascii
    $s9  = "m);return eNanY;}" fullword ascii
    $s10 = "function VEZubMJMKFBBlPDkUwZwAgYZWWQHbbttBqExMDmteoEEJWtmTbIfCe(eEzDOSiqUvfEi,ykjCFSRXajFJzK){ return QqbdsCw[TyZPLJUN[ZdgAQ(eEz" ascii
    $s11 = "function VEZubMJMKFBBlPDkUwZwAgYZWWQHbbttBqExMDmteoEEJWtmTbIfCe(eEzDOSiqUvfEi,ykjCFSRXajFJzK){ return QqbdsCw[TyZPLJUN[ZdgAQ(eEz" ascii
    $s12 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s13 = "function oSmNAPTJuPSOQMb(sLUXldsDOoOxzPtXG,voNuXkuiYiqTrAbnasttEtLRoAxaZWuQgm,xPNjBAdjQHdwJHdouBKtHFKiEsvYUfVFDrM){eval(sLUXldsD" ascii
    $s14 = "function ZdgAQ(CzeCEEJwQcx,CHsZTvWLLxstl,rURjBJLm){QvCL=sPOEXsyvRysEYCKty(CzeCEEJwQcx,CHsZTvWLLxstl);eNanY=QvCL.toString(rURjBJL" ascii
    $s15 = "function oSmNAPTJuPSOQMb(sLUXldsDOoOxzPtXG,voNuXkuiYiqTrAbnasttEtLRoAxaZWuQgm,xPNjBAdjQHdwJHdouBKtHFKiEsvYUfVFDrM){eval(sLUXldsD" ascii
    $s16 = "function sPOEXsyvRysEYCKty(gdekCyUjUB,CRyZwyxJNj) {return parseInt(gdekCyUjUB,CRyZwyxJNj);}" fullword ascii
    $s17 = "function phYTbDb(iqFczqYitvIniXsAbVkpCJSPRmyJtPhjeCZY) {return !gNzufHTSDzZ(xbozrcGNnzSrpLj(iqFczqYitvIniXsAbVkpCJSPRmyJtPhjeCZY" ascii
    $s18 = "function Y(liwEvnznVCbV,FIaFlZmJPpgRVr){liwEvnznVCbV.push(FIaFlZmJPpgRVr);}" fullword ascii
    $s19 = "function gNzufHTSDzZ(tHnhUOZHRdZgJb) {return isNaN(tHnhUOZHRdZgJb);}" fullword ascii
    $s20 = "function ZdgAQ(CzeCEEJwQcx,CHsZTvWLLxstl,rURjBJLm){QvCL=sPOEXsyvRysEYCKty(CzeCEEJwQcx,CHsZTvWLLxstl);eNanY=QvCL.toString(rURjBJL" ascii

  condition:
    uint16(0) == 0x7954 and
    8 of them
}