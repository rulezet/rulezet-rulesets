rule sig_20151217_33fd8f033914c8f4f8f4e87657e81a15 {
  meta:
    description = "datamaliciousorder - file 20151217_33fd8f033914c8f4f8f4e87657e81a15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f5023fa48fa8d38f8ea6dc1998bd1535dc96da4a1c5d24c45037f83bf97e7a"

  strings:
    $s1  = "function ontgoFdcLFFOodowb(pQicO){flTOTPAqLKW= '';VJKnJicAySd=Math.round((Math.pow(Math.sin(342), 2) + Math.pow(Math.cos(342), 2" ascii
    $s2  = ") - 1));while(true){if (VJKnJicAySd >= (548+808)/226){break;}uzzBSHRlb[VJKnJicAySd]=Math.round((Math.pow(Math.sin(288), 2) + Mat" ascii
    $s3  = "ow(Math.cos(347), 2) - 1)));} uzzBSHRlb[VJKnJicAySd]++;}VJKnJicAySd++;} return flTOTPAqLKW}" fullword ascii
    $s4  = "h.pow(Math.cos(288), 2) - 1)); while(true) { if(uzzBSHRlb[VJKnJicAySd] > pQicO[VJKnJicAySd].length-(388+144)/532) { break; } if " ascii
    $s5  = "function lgoSqWK(zitXJsEKAqVIPrzZVuhhFBFphFukgPGhKyKk) {return !YokbaNueVFv(tiYnAouiCyugIoW(zitXJsEKAqVIPrzZVuhhFBFphFukgPGhKyKk" ascii
    $s6  = "function ontgoFdcLFFOodowb(pQicO){flTOTPAqLKW= '';VJKnJicAySd=Math.round((Math.pow(Math.sin(342), 2) + Math.pow(Math.cos(342), 2" ascii
    $s7  = "function AvSgiEQyYXjZhNbiNWxdPQlxnGFJXRrEpWuJxjckvmGktvQjJbvBMO(WurVFJcwnwDqs,HvidPoMRlGATjM){ return mVAfboJ[EmqmUJoS[FzRYd(Wur" ascii
    $s8  = "function AvSgiEQyYXjZhNbiNWxdPQlxnGFJXRrEpWuJxjckvmGktvQjJbvBMO(WurVFJcwnwDqs,HvidPoMRlGATjM){ return mVAfboJ[EmqmUJoS[FzRYd(Wur" ascii
    $s9  = "function lgoSqWK(zitXJsEKAqVIPrzZVuhhFBFphFukgPGhKyKk) {return !YokbaNueVFv(tiYnAouiCyugIoW(zitXJsEKAqVIPrzZVuhhFBFphFukgPGhKyKk" ascii
    $s10 = "function b(impoClZEyIbG,pzCEGHmQausZGV){impoClZEyIbG.push(pzCEGHmQausZGV);}" fullword ascii
    $s11 = "b);return IrkqJ;}" fullword ascii
    $s12 = "function tiYnAouiCyugIoW(yTVAPdGpgODnICnoSeK) {return parseFloat(yTVAPdGpgODnICnoSeK);}" fullword ascii
    $s13 = "function FzRYd(vJmeRpIuVSN,ZdLMsSjzbvweT,EzYLPgRb){IfYr=OGsjWQFlgoBHfUdrv(vJmeRpIuVSN,ZdLMsSjzbvweT);IrkqJ=IfYr.toString(EzYLPgR" ascii
    $s14 = "function CVlQbXmUxtxYUDv(ocHMgscDEMizbgXKu,sCQMTIvVsPJijzVcefTAGWZqTKLOeDQxMi,oOSoGPOaSNZPAvCryfXqZuynOAbWorURQkG){eval(ocHMgscD" ascii
    $s15 = "function YokbaNueVFv(oEuIYfbxdXjFhv) {return isNaN(oEuIYfbxdXjFhv);}" fullword ascii
    $s16 = "function mCRiCkzelSLw(tPjTGWudgXNbU) {return isFinite(tPjTGWudgXNbU);}" fullword ascii
    $s17 = "function OGsjWQFlgoBHfUdrv(RxVlRjEzAH,uFLHYktKeA) {return parseInt(RxVlRjEzAH,uFLHYktKeA);}" fullword ascii
    $s18 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s19 = "function P(XKPOcosFwIuuST,qxjBvzkitCTsc,WaAyKIrJrPU) {XKPOcosFwIuuST[qxjBvzkitCTsc]=WaAyKIrJrPU;}" fullword ascii
    $s20 = "function FzRYd(vJmeRpIuVSN,ZdLMsSjzbvweT,EzYLPgRb){IfYr=OGsjWQFlgoBHfUdrv(vJmeRpIuVSN,ZdLMsSjzbvweT);IrkqJ=IfYr.toString(EzYLPgR" ascii

  condition:
    uint16(0) == 0x6d45 and
    8 of them
}