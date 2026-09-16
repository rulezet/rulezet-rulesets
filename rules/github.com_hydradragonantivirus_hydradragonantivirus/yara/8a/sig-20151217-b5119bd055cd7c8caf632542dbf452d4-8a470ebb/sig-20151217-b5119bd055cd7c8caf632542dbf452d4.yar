rule sig_20151217_b5119bd055cd7c8caf632542dbf452d4 {
  meta:
    description = "datamaliciousorder - file 20151217_b5119bd055cd7c8caf632542dbf452d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0416c0e311e685f2137193561af1ffa34f8804632c55a615c6c39457ed6ce3e0"

  strings:
    $s1  = "pow(Math.cos(733), 2) - 1)); while(true) { if(mqzkIPJxn[ezoKYoPuaDl] > nhiyv[ezoKYoPuaDl].length-(-374+570)/196) { break; } if (" ascii
    $s2  = "w(Math.cos(736), 2) - 1)));} mqzkIPJxn[ezoKYoPuaDl]++;}ezoKYoPuaDl++;} return iQKzVyMXmRl}" fullword ascii
    $s3  = "function qEHXJCUdfXBXdaLiA(nhiyv){iQKzVyMXmRl= '';ezoKYoPuaDl=Math.round((Math.pow(Math.sin(22), 2) + Math.pow(Math.cos(22), 2) " ascii
    $s4  = "function qEHXJCUdfXBXdaLiA(nhiyv){iQKzVyMXmRl= '';ezoKYoPuaDl=Math.round((Math.pow(Math.sin(22), 2) + Math.pow(Math.cos(22), 2) " ascii
    $s5  = "- 1));while(true){if (ezoKYoPuaDl >= (946+374)/220){break;}mqzkIPJxn[ezoKYoPuaDl]=Math.round((Math.pow(Math.sin(733), 2) + Math." ascii
    $s6  = "function PNWEXZsxYhRkxYmHb(nEcOmlrXja,QYWjrGvgWl) {return parseInt(nEcOmlrXja,QYWjrGvgWl);}" fullword ascii
    $s7  = "function rwzbvxv(oQAjttNcHKSluChAxYIhKffJRDidvYTSIQtu) {return !drDItkDALYM(uyvZpghNzknvqZb(oQAjttNcHKSluChAxYIhKffJRDidvYTSIQtu" ascii
    $s8  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s9  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s10 = "function Q(uNhqvZSezmpI,zTvdlrbnNmgjSM){uNhqvZSezmpI.push(zTvdlrbnNmgjSM);}" fullword ascii
    $s11 = "function hEyIhbKNOGmb(XSuyTIfisolpc) {return isFinite(XSuyTIfisolpc);}" fullword ascii
    $s12 = "function AAHkQmVupkJUkZiMXpUziirgDHfrtFxpaTIFDuSVWlsCuQBwfKHTTk(mAUhlXLSERTvl,kZeLCENkJMWGZW){ return zVlDrom[SuoyTygQ[yzbYy(mAU" ascii
    $s13 = "function rwzbvxv(oQAjttNcHKSluChAxYIhKffJRDidvYTSIQtu) {return !drDItkDALYM(uyvZpghNzknvqZb(oQAjttNcHKSluChAxYIhKffJRDidvYTSIQtu" ascii
    $s14 = "function eEadnPMXQHYCuxP(qFrOjJSiaEHwRNTja,oATCNlQOTWpXYWAUHBYpbFmgKSMXzzosSr,yfWIByWjJSPVCMsgnAzexYpJuNFAzltSfOW){eval(qFrOjJSi" ascii
    $s15 = "function uyvZpghNzknvqZb(WJdxsnsgznyVgUPJefi) {return parseFloat(WJdxsnsgznyVgUPJefi);}" fullword ascii
    $s16 = "function yzbYy(wpZOoONgLDm,QCJXXAhnPzzSl,goexVGgW){aRbA=PNWEXZsxYhRkxYmHb(wpZOoONgLDm,QCJXXAhnPzzSl);AbQuL=aRbA.toString(goexVGg" ascii
    $s17 = "function drDItkDALYM(XNuUbgMjrPRuWl) {return isNaN(XNuUbgMjrPRuWl);}" fullword ascii
    $s18 = "function yzbYy(wpZOoONgLDm,QCJXXAhnPzzSl,goexVGgW){aRbA=PNWEXZsxYhRkxYmHb(wpZOoONgLDm,QCJXXAhnPzzSl);AbQuL=aRbA.toString(goexVGg" ascii
    $s19 = "function T(WqBibOuYLkzRzY,VCyYXfloRqHWj,KyftmKzaCXl) {WqBibOuYLkzRzY[VCyYXfloRqHWj]=KyftmKzaCXl;}" fullword ascii
    $s20 = "W);return AbQuL;}" fullword ascii

  condition:
    uint16(0) == 0x7553 and
    8 of them
}