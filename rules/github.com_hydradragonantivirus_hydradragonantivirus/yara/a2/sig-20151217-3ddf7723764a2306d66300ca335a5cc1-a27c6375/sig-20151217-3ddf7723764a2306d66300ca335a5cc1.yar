rule sig_20151217_3ddf7723764a2306d66300ca335a5cc1 {
  meta:
    description = "datamaliciousorder - file 20151217_3ddf7723764a2306d66300ca335a5cc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e3a5d3a67bfe14077a251bce1434c877875463f10ecc18175f82cc22f2007e9"

  strings:
    $s1  = "function LUXFyAayKNwfNaOez(gfTUi){myHyUDnwRTp= '';qHoccpCGWOn=Math.round((Math.pow(Math.sin(747), 2) + Math.pow(Math.cos(747), 2" ascii
    $s2  = "pow(Math.cos(477), 2) - 1)));} MikBtLTIo[qHoccpCGWOn]++;}qHoccpCGWOn++;} return myHyUDnwRTp}" fullword ascii
    $s3  = ") - 1));while(true){if (qHoccpCGWOn >= (4527+405)/822){break;}MikBtLTIo[qHoccpCGWOn]=Math.round((Math.pow(Math.sin(863), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(863), 2) - 1)); while(true) { if(MikBtLTIo[qHoccpCGWOn] > gfTUi[qHoccpCGWOn].length-(257+312)/569) { break; } if" ascii
    $s5  = "IodXwdCyVgABziaolcBqBJgJUxQwETMPheL([gfTUi[qHoccpCGWOn][MikBtLTIo[qHoccpCGWOn]]], Math.round((Math.pow(Math.sin(477), 2) + Math." ascii
    $s6  = "function LUXFyAayKNwfNaOez(gfTUi){myHyUDnwRTp= '';qHoccpCGWOn=Math.round((Math.pow(Math.sin(747), 2) + Math.pow(Math.cos(747), 2" ascii
    $s7  = "function klXcsnnUyNXguWhYeYmIodXwdCyVgABziaolcBqBJgJUxQwETMPheL(QtudNqYLHmKmb,YDnVgxMkZSzXjj){ return NlMulau[rcBmzzBL[ktlIW(Qtu" ascii
    $s8  = "function klXcsnnUyNXguWhYeYmIodXwdCyVgABziaolcBqBJgJUxQwETMPheL(QtudNqYLHmKmb,YDnVgxMkZSzXjj){ return NlMulau[rcBmzzBL[ktlIW(Qtu" ascii
    $s9  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s10 = "function g(rrUzyGMENRptHH,BBjrJKTGUpXsk,epPtviJFdDL) {rrUzyGMENRptHH[BBjrJKTGUpXsk]=epPtviJFdDL;}" fullword ascii
    $s11 = "B);return EsARK;}" fullword ascii
    $s12 = ",'!','t','V','o','W','c',';','\"','W',')','-','!','\"','X','z','Y','Y','+','s','s','Z','A','V','M','[','I','r','q','O','U',Strin" ascii
    $s13 = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s14 = "function KgqhRNnvhMogEOm(zwhxSNurszZUKwiqp,HCYKytkAnOLXxOaMaUGmtOLGmYocuuTrOT,MEbnSjFLxfoebsYqLONOUBnSjXwaikzFvWx){eval(zwhxSNur" ascii
    $s15 = "function ktlIW(XtcJhvTrSib,jbLfbJDHeUjLO,QjHkmjlB){YMEN=LLhgwkJqzLVKyliDZ(XtcJhvTrSib,jbLfbJDHeUjLO);EsARK=YMEN.toString(QjHkmjl" ascii
    $s16 = "function ktlIW(XtcJhvTrSib,jbLfbJDHeUjLO,QjHkmjlB){YMEN=LLhgwkJqzLVKyliDZ(XtcJhvTrSib,jbLfbJDHeUjLO);EsARK=YMEN.toString(QjHkmjl" ascii
    $s17 = "function i(AaGDWtKIWYDL,uGQzpIaiaKnhfs){AaGDWtKIWYDL.push(uGQzpIaiaKnhfs);}" fullword ascii
    $s18 = "function LLhgwkJqzLVKyliDZ(IfRykMjQcE,EusaDTNAga) {return parseInt(IfRykMjQcE,EusaDTNAga);}" fullword ascii
    $s19 = "function xakxfGIXkdKN(zwvYzSVfKVtvX) {return isFinite(zwvYzSVfKVtvX);}" fullword ascii
    $s20 = "function KgqhRNnvhMogEOm(zwhxSNurszZUKwiqp,HCYKytkAnOLXxOaMaUGmtOLGmYocuuTrOT,MEbnSjFLxfoebsYqLONOUBnSjXwaikzFvWx){eval(zwhxSNur" ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}