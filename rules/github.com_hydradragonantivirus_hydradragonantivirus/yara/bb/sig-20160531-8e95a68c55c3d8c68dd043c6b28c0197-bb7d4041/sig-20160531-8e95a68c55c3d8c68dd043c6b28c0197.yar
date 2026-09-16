rule sig_20160531_8e95a68c55c3d8c68dd043c6b28c0197 {
  meta:
    description = "datamaliciousorder - file 20160531_8e95a68c55c3d8c68dd043c6b28c0197.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62394e08dc32a5d22b99d2fe41223697e07874685974691eb73a2b75814d9063"

  strings:
    $s1  = "function kPnXTIkZsdVQHuto(WJHPSuKEyOEKLOolgZSTs,QtzmBqnqoAVeOXWsAjDnANo){return WJHPSuKEyOEKLOolgZSTs.charAt(QtzmBqnqoAVeOXWsAjD" ascii
    $s2  = "function kPnXTIkZsdVQHuto(WJHPSuKEyOEKLOolgZSTs,QtzmBqnqoAVeOXWsAjDnANo){return WJHPSuKEyOEKLOolgZSTs.charAt(QtzmBqnqoAVeOXWsAjD" ascii
    $s3  = "var ioLcHnjRxXwaX=function(){return WScript.CreateObject(EbgSKbFVHphQBAayonoPh[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s4  = "function DkIyxrC(eNwZFiErFKZlw) {var ElmNIHKGxKjsIwQyIuCx = mPOzf.join(EbgSKbFVHphQBAayonoPh[7]);var iXjQEajKnNJrCdTPYjuKCR, SaS" ascii
    $s5  = "(edVEUi,0x1,0x0)}function ISlLhCR(QtnsUroZWhzgOw,mQmKhVj,xXeMGx){var EdgHPRoh=QtnsUroZWhzgOw.createtextfile(mQmKhVj,true);EdgHPR" ascii
    $s6  = "function HkCIcTUDlKv(SMqqMroEfBN,xrAuU){return SMqqMroEfBN.indexOf(xrAuU);}" fullword ascii
    $s7  = "function joFgaMjiCMNEB(PpZLuBdGIg,eqhXIAMjQ,lirgLAjGvScC){ANISnrd=PpZLuBdGIg.split(lirgLAjGvScC);elOTPtp = EbgSKbFVHphQBAayonoPh" ascii
    $s8  = "[0];for(IegiBnWkwH=0;IegiBnWkwH<eqhXIAMjQ.length;IegiBnWkwH++) {elOTPtp+=ANISnrd[eqhXIAMjQ[IegiBnWkwH]];}return elOTPtp.substrin" ascii
    $s9  = "function eJAuCYBN(){return joFgaMjiCMNEB(EbgSKbFVHphQBAayonoPh[9],[1,5,7],EbgSKbFVHphQBAayonoPh[10]);}" fullword ascii
    $s10 = "function DkIyxrC(eNwZFiErFKZlw) {var ElmNIHKGxKjsIwQyIuCx = mPOzf.join(EbgSKbFVHphQBAayonoPh[7]);var iXjQEajKnNJrCdTPYjuKCR, SaS" ascii
    $s11 = "function bNkfKLNXfGu(){return joFgaMjiCMNEB(EbgSKbFVHphQBAayonoPh[13],[0,3,6],EbgSKbFVHphQBAayonoPh[14]);}" fullword ascii
    $s12 = "ngth);return hVtNCUSblky;}" fullword ascii
    $s13 = "function CEoCiQLZNZlouYEVjWBv(OYSCwlMYSbltn,YertHIWCRNlYJtKQvEKSCw){return String.fromCharCode(OYSCwlMYSbltn,YertHIWCRNlYJtKQvEK" ascii
    $s14 = "function eZRjchDVTXOYOq(){return ioLcHnjRxXwaX.ExpandEnvironmentStrings(eJAuCYBN())}" fullword ascii
    $s15 = "(edVEUi,0x1,0x0)}function ISlLhCR(QtnsUroZWhzgOw,mQmKhVj,xXeMGx){var EdgHPRoh=QtnsUroZWhzgOw.createtextfile(mQmKhVj,true);EdgHPR" ascii
    $s16 = "function u(XXbaqTgXyHJWBQAyw){return String.fromCharCode(XXbaqTgXyHJWBQAyw);}" fullword ascii
    $s17 = "function CEoCiQLZNZlouYEVjWBv(OYSCwlMYSbltn,YertHIWCRNlYJtKQvEKSCw){return String.fromCharCode(OYSCwlMYSbltn,YertHIWCRNlYJtKQvEK" ascii
    $s18 = "var xUQrOLMmwuUma=function(){return new ActiveXObject(EbgSKbFVHphQBAayonoPh[1]);}();" fullword ascii
    $s19 = "function kFyDLFjCvSpZteBpltQR(uTYKQ,xyYfKzYaPotNnAI,ZggoLNtKYwOd){return String.fromCharCode(uTYKQ,xyYfKzYaPotNnAI,ZggoLNtKYwOd)" ascii
    $s20 = "function RqEpQeUxaihFk(kIMMC,edVEUi) {var ftsjOVkmazWUay=[EbgSKbFVHphQBAayonoPh[15]];kIMMC[ftsjOVkmazWUay[0]]" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}