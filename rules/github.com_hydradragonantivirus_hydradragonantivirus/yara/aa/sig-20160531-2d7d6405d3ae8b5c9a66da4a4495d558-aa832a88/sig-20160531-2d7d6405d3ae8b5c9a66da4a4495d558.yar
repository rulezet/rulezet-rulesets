rule sig_20160531_2d7d6405d3ae8b5c9a66da4a4495d558 {
  meta:
    description = "datamaliciousorder - file 20160531_2d7d6405d3ae8b5c9a66da4a4495d558.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94a931e46856b3fa9a9bd221b97d4127ab975c4c2eab00f1e7de7069acf44e5c"

  strings:
    $s1  = "function zyQWLDmvdOGwkyOMaMpvj(tVimrWoBbsk,mkdIcFF){return tVimrWoBbsk.charAt(mkdIcFF);}" fullword ascii
    $s2  = "var otKMFfopoyH=function(){return WScript.CreateObject(ReEYSeXUQujCAurYyyLDp[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "MfUiIzSXLqPDXcPlojs, esEafI);} while (FjjTchJ < zBmhdiExoAohR.length);return CQYDNOnP;}" fullword ascii
    $s4  = "function rcpzZHAjKnHcVkpwFB(JXGLdBnGCYa,dahkgE){return String.fromCharCode(JXGLdBnGCYa,dahkgE);}" fullword ascii
    $s5  = "g(JmiMQ);else if (gtSvTZOPyl == 64) CQYDNOnP += rcpzZHAjKnHcVkpwFB(JmiMQ, aMfUiIzSXLqPDXcPlojs);else CQYDNOnP += ErMtNt(JmiMQ, a" ascii
    $s6  = "function ErMtNt(hjjCzaztvkIGOLiLEk,rjgOvTzkCpDAIkQLhaaLwg,PpEWMWCrDDzS){return String.fromCharCode(hjjCzaztvkIGOLiLEk,rjgOvTzkCp" ascii
    $s7  = "function ErMtNt(hjjCzaztvkIGOLiLEk,rjgOvTzkCpDAIkQLhaaLwg,PpEWMWCrDDzS){return String.fromCharCode(hjjCzaztvkIGOLiLEk,rjgOvTzkCp" ascii
    $s8  = "OSafocy<Kvujbnv.length;OSafocy++) {juyjWt+=gYeGJrqEZpY[Kvujbnv[OSafocy]];}return juyjWt.substring(3,juyjWt.length);}" fullword ascii
    $s9  = "function Jg(cBLcyVg){return String.fromCharCode(cBLcyVg);}" fullword ascii
    $s10 = "(gtVoAdPiTx,0x1,0x0)}function FyQUOkWYM(QNzGOIDY,BjPoQETHS,OfvQjrT){var QxWDzzlrFJ=QNzGOIDY.createtextfile(BjPoQETHS,true);QxWDz" ascii
    $s11 = "(gtVoAdPiTx,0x1,0x0)}function FyQUOkWYM(QNzGOIDY,BjPoQETHS,OfvQjrT){var QxWDzzlrFJ=QNzGOIDY.createtextfile(BjPoQETHS,true);QxWDz" ascii
    $s12 = "function GKjmYdJSbm(){return otKMFfopoyH.ExpandEnvironmentStrings(nonqm())}" fullword ascii
    $s13 = "function ybyraeRQFDZyVkpr(pDKxXX,rtdkRBeobdGGLJ){return pDKxXX.indexOf(rtdkRBeobdGGLJ);}" fullword ascii
    $s14 = "function nonqm(){return nsBXNI(ReEYSeXUQujCAurYyyLDp[9],[1,5,7],ReEYSeXUQujCAurYyyLDp[10]);}" fullword ascii
    $s15 = "function FjTHFNRt(){return nsBXNI(ReEYSeXUQujCAurYyyLDp[13],[0,3,6],ReEYSeXUQujCAurYyyLDp[14]);}" fullword ascii
    $s16 = "var gwcUhjJax=function(){return new ActiveXObject(ReEYSeXUQujCAurYyyLDp[1]);}();" fullword ascii
    $s17 = "function nsBXNI(sBBqFkTmMY,Kvujbnv,JBexOi){gYeGJrqEZpY=sBBqFkTmMY.split(JBexOi);juyjWt = ReEYSeXUQujCAurYyyLDp[0];for(OSafocy=0;" ascii
    $s18 = "function CFStHwxxgOLiLg(zBmhdiExoAohR) {var OqothB = DtLoMOReHsGFNjeHluCWrF.join(ReEYSeXUQujCAurYyyLDp[7]);var JmiMQ, aMfUiIzSXL" ascii
    $s19 = "function nsBXNI(sBBqFkTmMY,Kvujbnv,JBexOi){gYeGJrqEZpY=sBBqFkTmMY.split(JBexOi);juyjWt = ReEYSeXUQujCAurYyyLDp[0];for(OSafocy=0;" ascii
    $s20 = "function bvozYWFi(){return nsBXNI(ReEYSeXUQujCAurYyyLDp[11],[2,4,8,10],ReEYSeXUQujCAurYyyLDp[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}