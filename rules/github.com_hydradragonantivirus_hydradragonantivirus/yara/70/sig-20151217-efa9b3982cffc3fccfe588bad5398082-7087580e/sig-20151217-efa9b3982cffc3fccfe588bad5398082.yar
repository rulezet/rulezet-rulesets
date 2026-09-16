rule sig_20151217_efa9b3982cffc3fccfe588bad5398082 {
  meta:
    description = "datamaliciousorder - file 20151217_efa9b3982cffc3fccfe588bad5398082.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fa9c25d27c303c26cfe0e01bad6a08e5fda846be35951e3d0765cac570428f0"

  strings:
    $s1  = "function zFaDlGzOaGvEdToyv(AHuqi){xEHWlvrkxZT= '';qOkGosYQwLz=Math.round((Math.pow(Math.sin(136), 2) + Math.pow(Math.cos(136), 2" ascii
    $s2  = "(Math.cos(433), 2) - 1)));} zACDuEnAW[qOkGosYQwLz]++;}qOkGosYQwLz++;} return xEHWlvrkxZT}" fullword ascii
    $s3  = ") - 1));while(true){if (qOkGosYQwLz >= (2952+396)/558){break;}zACDuEnAW[qOkGosYQwLz]=Math.round((Math.pow(Math.sin(532), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(532), 2) - 1)); while(true) { if(zACDuEnAW[qOkGosYQwLz] > AHuqi[qOkGosYQwLz].length-(-805+892)/87) { break; } if" ascii
    $s5  = "function zFaDlGzOaGvEdToyv(AHuqi){xEHWlvrkxZT= '';qOkGosYQwLz=Math.round((Math.pow(Math.sin(136), 2) + Math.pow(Math.cos(136), 2" ascii
    $s6  = "function k(IVXlxiWpZijbpx,xqwkeYuViibhR,nHJMimqThAc) {IVXlxiWpZijbpx[xqwkeYuViibhR]=nHJMimqThAc;}" fullword ascii
    $s7  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s8  = "function LObMsEfDUCBRSHLSejCUoaNQBudPvPQgrFvlOADUalEuEzNUZenWED(oIRFfFKBGKdIY,uxAKaIziDyMbOh){ return KJmRwHC[AuXGlipj[QdvWp(oIR" ascii
    $s9  = "function LObMsEfDUCBRSHLSejCUoaNQBudPvPQgrFvlOADUalEuEzNUZenWED(oIRFfFKBGKdIY,uxAKaIziDyMbOh){ return KJmRwHC[AuXGlipj[QdvWp(oIR" ascii
    $s10 = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s11 = "function KNFQmlrjimW(yDzTauBKzAdQJL) {return isNaN(yDzTauBKzAdQJL);}" fullword ascii
    $s12 = "function HuZoulVsKgkCkoV(XydeMIdpTPMryPfLcuS) {return parseFloat(XydeMIdpTPMryPfLcuS);}" fullword ascii
    $s13 = "function HrdZsBPWmoxxuhi(FlZhknNBXaexbXJrj,gOLGpNPKXYRmwfyZnBGyWSmZhtMGJJEZSy,wOTIMQsMtZTBjVKXlJjYEUaaTfdfIakIXTh){eval(FlZhknNB" ascii
    $s14 = "function ufaguGcedcqlwQXgH(NDytLnaIxb,tpKPDugvjL) {return parseInt(NDytLnaIxb,tpKPDugvjL);}" fullword ascii
    $s15 = "function HrdZsBPWmoxxuhi(FlZhknNBXaexbXJrj,gOLGpNPKXYRmwfyZnBGyWSmZhtMGJJEZSy,wOTIMQsMtZTBjVKXlJjYEUaaTfdfIakIXTh){eval(FlZhknNB" ascii
    $s16 = "function C(uVvkuRSBsgyN,sAbyaOBDegLAEq){uVvkuRSBsgyN.push(sAbyaOBDegLAEq);}" fullword ascii
    $s17 = "function YqVtlTl(YJdLsRiULXPxDUfCsiVLuKeKdmjtBGuVGYCu) {return !KNFQmlrjimW(HuZoulVsKgkCkoV(YJdLsRiULXPxDUfCsiVLuKeKdmjtBGuVGYCu" ascii
    $s18 = "function YqVtlTl(YJdLsRiULXPxDUfCsiVLuKeKdmjtBGuVGYCu) {return !KNFQmlrjimW(HuZoulVsKgkCkoV(YJdLsRiULXPxDUfCsiVLuKeKdmjtBGuVGYCu" ascii
    $s19 = "function QdvWp(mtSebjaZTvM,GpHNUWKOwrPap,XmgTQmgg){aEtM=ufaguGcedcqlwQXgH(mtSebjaZTvM,GpHNUWKOwrPap);caCXr=aEtM.toString(XmgTQmg" ascii
    $s20 = "function tmlzPXRagCAn(zJfYNTaamOFul) {return isFinite(zJfYNTaamOFul);}" fullword ascii

  condition:
    uint16(0) == 0x7541 and
    8 of them
}