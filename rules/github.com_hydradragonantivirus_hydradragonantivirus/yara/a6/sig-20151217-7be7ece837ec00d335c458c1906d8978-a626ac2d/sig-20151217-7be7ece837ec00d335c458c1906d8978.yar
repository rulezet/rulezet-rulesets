rule sig_20151217_7be7ece837ec00d335c458c1906d8978 {
  meta:
    description = "datamaliciousorder - file 20151217_7be7ece837ec00d335c458c1906d8978.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23da864caa0df478fd6eaed5320ac7ec75200acb9db399eafae23b67b9faffd4"

  strings:
    $s1  = "(Math.cos(558), 2) - 1)));} wgEghpUPq[NMyVYLMeJTf]++;}NMyVYLMeJTf++;} return nWZnSVuSNky}" fullword ascii
    $s2  = "function PNmireYjoWaonpJlD(OMSvt){nWZnSVuSNky= '';NMyVYLMeJTf=Math.round((Math.pow(Math.sin(590), 2) + Math.pow(Math.cos(590), 2" ascii
    $s3  = ") - 1));while(true){if (NMyVYLMeJTf >= (4174+434)/768){break;}wgEghpUPq[NMyVYLMeJTf]=Math.round((Math.pow(Math.sin(836), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(836), 2) - 1)); while(true) { if(wgEghpUPq[NMyVYLMeJTf] > OMSvt[NMyVYLMeJTf].length-(-268+278)/10) { break; } if" ascii
    $s5  = "function PNmireYjoWaonpJlD(OMSvt){nWZnSVuSNky= '';NMyVYLMeJTf=Math.round((Math.pow(Math.sin(590), 2) + Math.pow(Math.cos(590), 2" ascii
    $s6  = "function LgqMXlf(eCMuuqtCPsKCBpWWGotfHYMerMZwqdhtnXyg) {return !vBmgLOBlgUR(celoiRNooApRdLR(eCMuuqtCPsKCBpWWGotfHYMerMZwqdhtnXyg" ascii
    $s7  = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s8  = "function htwPufOCFwhtborHlAthrFdJZaJlonXuHJjJTHovpSiqhNDPBUndKe(hCyrBADFstVcu,HBZZbyhdshBhbD){ return rItUXvL[oGPMFpLW[qVtgh(hCy" ascii
    $s9  = "function U(leRpwLDGZqaetI,UigRBQkEVrClq,AUbdtTiOkKE) {leRpwLDGZqaetI[UigRBQkEVrClq]=AUbdtTiOkKE;}" fullword ascii
    $s10 = "function LgqMXlf(eCMuuqtCPsKCBpWWGotfHYMerMZwqdhtnXyg) {return !vBmgLOBlgUR(celoiRNooApRdLR(eCMuuqtCPsKCBpWWGotfHYMerMZwqdhtnXyg" ascii
    $s11 = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s12 = "t);return HOzNI;}" fullword ascii
    $s13 = "function ogRRVozZejFSGFg(YejyFfjrKCyDTogpi,qRNmBfqSqZwbNPlBhLviHWceMUNxJgSWux,YSsQWGXfiMbLGcJvHOFfLqJecmrjKVQkzZx){eval(YejyFfjr" ascii
    $s14 = "function paTeTodbixbzVbWLs(xzrwZrphoK,aVCdffuEUf) {return parseInt(xzrwZrphoK,aVCdffuEUf);}" fullword ascii
    $s15 = "function celoiRNooApRdLR(zrSvrDdPghobALxcSKf) {return parseFloat(zrSvrDdPghobALxcSKf);}" fullword ascii
    $s16 = "function vBmgLOBlgUR(gVEyIkrLmaOrWZ) {return isNaN(gVEyIkrLmaOrWZ);}" fullword ascii
    $s17 = "function qVtgh(EfwzyDgCSaQ,wlfjbRiMTJGRT,GKXPGbRt){OqFo=paTeTodbixbzVbWLs(EfwzyDgCSaQ,wlfjbRiMTJGRT);HOzNI=OqFo.toString(GKXPGbR" ascii
    $s18 = "function y(aVbDXtdTaEnz,dDSsbYVZlXjHrR){aVbDXtdTaEnz.push(dDSsbYVZlXjHrR);}" fullword ascii
    $s19 = "function AGacNnqAbQCS(LWhrwJIUbtAHv) {return isFinite(LWhrwJIUbtAHv);}" fullword ascii
    $s20 = "function ogRRVozZejFSGFg(YejyFfjrKCyDTogpi,qRNmBfqSqZwbNPlBhLviHWceMUNxJgSWux,YSsQWGXfiMbLGcJvHOFfLqJecmrjKVQkzZx){eval(YejyFfjr" ascii

  condition:
    uint16(0) == 0x476f and
    8 of them
}