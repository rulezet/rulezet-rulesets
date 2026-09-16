rule sig_20151216_1519d9d8297602f5b57f15b09a7de597 {
  meta:
    description = "datamaliciousorder - file 20151216_1519d9d8297602f5b57f15b09a7de597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9671314f74041f4040f80ed563df90a2a12b49e1aa3c79bb070283817878fabe"

  strings:
    $s1  = ".pow(Math.cos(875), 2) - 1)); while(true) { if(UlVMyckxm[PnBqTWNbNUV] > RJgvm[PnBqTWNbNUV].length-(-461+930)/469) { break; } if " ascii
    $s2  = "function wEFfKfpqYcETciADZ(RJgvm){zukmfWGSsXq= '';PnBqTWNbNUV=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos(89), 2) " ascii
    $s3  = "(Math.cos(92), 2) - 1)));} UlVMyckxm[PnBqTWNbNUV]++;}PnBqTWNbNUV++;} return zukmfWGSsXq}" fullword ascii
    $s4  = "- 1));while(true){if (PnBqTWNbNUV >= (3332+130)/577){break;}UlVMyckxm[PnBqTWNbNUV]=Math.round((Math.pow(Math.sin(875), 2) + Math" ascii
    $s5  = "function wEFfKfpqYcETciADZ(RJgvm){zukmfWGSsXq= '';PnBqTWNbNUV=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos(89), 2) " ascii
    $s6  = "function AdQbXUc(jLHoMBIHRLEuXAUEqcMOuYAFAStKJOZdoMMQ) {return !nOCHUbwZcpo(aAqhZLkNYhVRFOZ(jLHoMBIHRLEuXAUEqcMOuYAFAStKJOZdoMMQ" ascii
    $s7  = "function MfIVTxELmlYBtGTjcgjfnMUCBCFpGuBafTohlLOsMHiWlSKdBecuGD(KTIKzGuEzjEsR,urepsktwVtalLU){ return MBvrapL[hxJKyNzr[nxzyX(KTI" ascii
    $s8  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s9  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s10 = "function nxzyX(ZdEKWHhiqMO,QRPZNlmHKZlyT,XTFJtEKj){tHlH=IrdIqxPoPjKFaFwIv(ZdEKWHhiqMO,QRPZNlmHKZlyT);VIGLa=tHlH.toString(XTFJtEK" ascii
    $s11 = "function nOCHUbwZcpo(kcLyiNvAvhdbtD) {return isNaN(kcLyiNvAvhdbtD);}" fullword ascii
    $s12 = "function MfIVTxELmlYBtGTjcgjfnMUCBCFpGuBafTohlLOsMHiWlSKdBecuGD(KTIKzGuEzjEsR,urepsktwVtalLU){ return MBvrapL[hxJKyNzr[nxzyX(KTI" ascii
    $s13 = "function V(SiCdeZSQvrqk,nRfTcHaLlsneKj){SiCdeZSQvrqk.push(nRfTcHaLlsneKj);}" fullword ascii
    $s14 = "function AdQbXUc(jLHoMBIHRLEuXAUEqcMOuYAFAStKJOZdoMMQ) {return !nOCHUbwZcpo(aAqhZLkNYhVRFOZ(jLHoMBIHRLEuXAUEqcMOuYAFAStKJOZdoMMQ" ascii
    $s15 = "function S(eSQoNULOIhkHOp,RIQKrqHYCofsr,qNJCKTQgQvR) {eSQoNULOIhkHOp[RIQKrqHYCofsr]=qNJCKTQgQvR;}" fullword ascii
    $s16 = "function nxzyX(ZdEKWHhiqMO,QRPZNlmHKZlyT,XTFJtEKj){tHlH=IrdIqxPoPjKFaFwIv(ZdEKWHhiqMO,QRPZNlmHKZlyT);VIGLa=tHlH.toString(XTFJtEK" ascii
    $s17 = "function aAqhZLkNYhVRFOZ(tpapdEiDoGdsPpunlSi) {return parseFloat(tpapdEiDoGdsPpunlSi);}" fullword ascii
    $s18 = "j);return VIGLa;}" fullword ascii
    $s19 = "function IrdIqxPoPjKFaFwIv(ZbkUxxSqEv,lKemJrkXIl) {return parseInt(ZbkUxxSqEv,lKemJrkXIl);}" fullword ascii
    $s20 = "function evULcGlXjVdb(FsGYfyxgOgxLk) {return isFinite(FsGYfyxgOgxLk);}" fullword ascii

  condition:
    uint16(0) == 0x7868 and
    8 of them
}