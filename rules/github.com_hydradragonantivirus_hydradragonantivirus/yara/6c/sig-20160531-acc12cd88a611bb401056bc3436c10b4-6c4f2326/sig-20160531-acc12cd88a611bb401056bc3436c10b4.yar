rule sig_20160531_acc12cd88a611bb401056bc3436c10b4 {
  meta:
    description = "datamaliciousorder - file 20160531_acc12cd88a611bb401056bc3436c10b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d76f8adbf11d30ff74bbe0a2b9ce10be048ba93cbb80a4ce50a65c787a7c33a6"

  strings:
    $s1  = "var AYsMFloJm=function(){return WScript.CreateObject(eQtznXt[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function hepouFUi(kgmkjdvs,CcWZsIjXqYBeqtLf){return kgmkjdvs.charAt(CcWZsIjXqYBeqtLf);}" fullword ascii
    $s3  = "g=0;GzCtgfg<ycljWC.length;GzCtgfg++) {mVpMQtQhUqcN+=IONXtwSxu[ycljWC[GzCtgfg]];}return mVpMQtQhUqcN.substring(3,mVpMQtQhUqcN.len" ascii
    $s4  = ");} while (wZqPPPFDpnoua < hqCQWtYzHOoHE.length);return peCumsBteciwxduP;}" fullword ascii
    $s5  = "var tVNcys=function(){return new ActiveXObject(eQtznXt[1]);}();" fullword ascii
    $s6  = "iwxduP += FtUfbuRHqbcbj(wnKDKDExAjt, skOUmtZwdJAql);else peCumsBteciwxduP += uWoSTjvSMgGkohi(wnKDKDExAjt, skOUmtZwdJAql, oDNGMSL" ascii
    $s7  = "function eHkRZBWSex(){return oLSLXNTki(eQtznXt[13],[0,3,6],eQtznXt[14]);}" fullword ascii
    $s8  = "(nAilkIBgUFkMc,0x1,0x0)}function inonjsFXzLAhE(UoDvDiP,mWtoX,jrwlQ){var Lxhlu=UoDvDiP.createtextfile(mWtoX,true);Lxhlu.WriteLine" ascii
    $s9  = "function FtUfbuRHqbcbj(RIDFbNkdTcW,cVzxYZybtOYLDNs){return String.fromCharCode(RIDFbNkdTcW,cVzxYZybtOYLDNs);}" fullword ascii
    $s10 = "function ulbQzpRKJL(uIAObz,nAilkIBgUFkMc) {var qfsvoYtbZwoeE=[eQtznXt[15]];uIAObz[qfsvoYtbZwoeE[0]]" fullword ascii
    $s11 = "function mapVdYK(){return oLSLXNTki(eQtznXt[9],[1,5,7],eQtznXt[10]);}" fullword ascii
    $s12 = "function KGxdTN(){return AYsMFloJm.ExpandEnvironmentStrings(mapVdYK())}" fullword ascii
    $s13 = "function oLSLXNTki(FoBWjpGj,ycljWC,elLGHVPOVqoPhO){IONXtwSxu=FoBWjpGj.split(elLGHVPOVqoPhO);mVpMQtQhUqcN = eQtznXt[0];for(GzCtgf" ascii
    $s14 = "f;oDNGMSL = yyBDOudvssES & 0xff;if (VpaKGatDsStBUX == 64) peCumsBteciwxduP += JR(wnKDKDExAjt);else if (yeOhsFA == 64) peCumsBtec" ascii
    $s15 = "(nAilkIBgUFkMc,0x1,0x0)}function inonjsFXzLAhE(UoDvDiP,mWtoX,jrwlQ){var Lxhlu=UoDvDiP.createtextfile(mWtoX,true);Lxhlu.WriteLine" ascii
    $s16 = "function wJEUti(hqCQWtYzHOoHE) {var pOFwUNVZkTEpKfbWone = jyssyssIX.join(eQtznXt[7]);var wnKDKDExAjt, skOUmtZwdJAql, oDNGMSL, iI" ascii
    $s17 = "function wJEUti(hqCQWtYzHOoHE) {var pOFwUNVZkTEpKfbWone = jyssyssIX.join(eQtznXt[7]);var wnKDKDExAjt, skOUmtZwdJAql, oDNGMSL, iI" ascii
    $s18 = "function JR(GuJPCCMJRQGrljSF){return String.fromCharCode(GuJPCCMJRQGrljSF);}" fullword ascii
    $s19 = "function oLSLXNTki(FoBWjpGj,ycljWC,elLGHVPOVqoPhO){IONXtwSxu=FoBWjpGj.split(elLGHVPOVqoPhO);mVpMQtQhUqcN = eQtznXt[0];for(GzCtgf" ascii
    $s20 = "function kmRvuztGDph(){return oLSLXNTki(eQtznXt[11],[2,4,8,10],eQtznXt[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}