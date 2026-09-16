rule sig_20151217_a0db8f61bf19d28e41d58857417cdda9 {
  meta:
    description = "datamaliciousorder - file 20151217_a0db8f61bf19d28e41d58857417cdda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20d8e5ffa328bd78ec2857f86229ac603d00d0a0e5503ed63cfea13a205faa10"

  strings:
    $s1  = "function tdGdVZVzGEyEBNVOT(ASGeA){QpEKscxEMMz= '';MvmHDKhKrCj=Math.round((Math.pow(Math.sin(741), 2) + Math.pow(Math.cos(741), 2" ascii
    $s2  = "function tdGdVZVzGEyEBNVOT(ASGeA){QpEKscxEMMz= '';MvmHDKhKrCj=Math.round((Math.pow(Math.sin(741), 2) + Math.pow(Math.cos(741), 2" ascii
    $s3  = "ow(Math.cos(147), 2) - 1)));} FnRyQMCff[MvmHDKhKrCj]++;}MvmHDKhKrCj++;} return QpEKscxEMMz}" fullword ascii
    $s4  = "th.pow(Math.cos(863), 2) - 1)); while(true) { if(FnRyQMCff[MvmHDKhKrCj] > ASGeA[MvmHDKhKrCj].length-(152+129)/281) { break; } if" ascii
    $s5  = ") - 1));while(true){if (MvmHDKhKrCj >= (5395+293)/948){break;}FnRyQMCff[MvmHDKhKrCj]=Math.round((Math.pow(Math.sin(863), 2) + Ma" ascii
    $s6  = "function hZtDAYq(ZJCJneaSCQOKtWHXPnmNgUhOeapXBxqxsJZk) {return !WSOGoxQhKhu(YAdVMsyZcdjaqSp(ZJCJneaSCQOKtWHXPnmNgUhOeapXBxqxsJZk" ascii
    $s7  = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s8  = "function w(zSynGsPtNteNoG,EKcRwOrUYwVWN,hTqNVJOYFMX) {zSynGsPtNteNoG[EKcRwOrUYwVWN]=hTqNVJOYFMX;}" fullword ascii
    $s9  = "function U(iibdYyXUsJfE,MCWZILyIgtCiLh){iibdYyXUsJfE.push(MCWZILyIgtCiLh);}" fullword ascii
    $s10 = "function xLOwNLFpKEigEdsHjSJfoulxrFRyNjiQRFUyjeXnFpAancqWdlRkEh(ZWmRtdJRYPtBC,TBGulgQQGECRit){ return VhGChbH[TpjJckMk[MAmHA(ZWm" ascii
    $s11 = "var M = new Array();M[0]=[];M[0][0]='d';M[0][1]='a';M[0][2]='d';M[0][3]='a';M[0][4]='46';M[0][5]='3d';M[0][6]='42';M[0][7]='14';" ascii
    $s12 = "function YAdVMsyZcdjaqSp(hsBSACnsetbMdzOHyrs) {return parseFloat(hsBSACnsetbMdzOHyrs);}" fullword ascii
    $s13 = "function MAmHA(WqpfyesjXsw,kyzoVTWUYhZSS,uvTQCbxA){MtsU=EVxwBMHikRMWrftcP(WqpfyesjXsw,kyzoVTWUYhZSS);drGHT=MtsU.toString(uvTQCbx" ascii
    $s14 = "function xLOwNLFpKEigEdsHjSJfoulxrFRyNjiQRFUyjeXnFpAancqWdlRkEh(ZWmRtdJRYPtBC,TBGulgQQGECRit){ return VhGChbH[TpjJckMk[MAmHA(ZWm" ascii
    $s15 = "function XeFHcGiAMLuOuVB(JRlpokhutCrVABfdz,plSOvwuHqHqYrbpiMgaZFnWTrtPXYNkUyw,tFdCqnyVRFrQFIipCttTiofySJQThrXPfdB){eval(JRlpokhu" ascii
    $s16 = "function MAmHA(WqpfyesjXsw,kyzoVTWUYhZSS,uvTQCbxA){MtsU=EVxwBMHikRMWrftcP(WqpfyesjXsw,kyzoVTWUYhZSS);drGHT=MtsU.toString(uvTQCbx" ascii
    $s17 = "function MBoktabupnxH(lQzOrtKwQLkgc) {return isFinite(lQzOrtKwQLkgc);}" fullword ascii
    $s18 = "function XeFHcGiAMLuOuVB(JRlpokhutCrVABfdz,plSOvwuHqHqYrbpiMgaZFnWTrtPXYNkUyw,tFdCqnyVRFrQFIipCttTiofySJQThrXPfdB){eval(JRlpokhu" ascii
    $s19 = "function EVxwBMHikRMWrftcP(ccMTogfFXW,FpVqTvSvJl) {return parseInt(ccMTogfFXW,FpVqTvSvJl);}" fullword ascii
    $s20 = "function WSOGoxQhKhu(VSLsWPFxfZMPrG) {return isNaN(VSLsWPFxfZMPrG);}" fullword ascii

  condition:
    uint16(0) == 0x7054 and
    8 of them
}