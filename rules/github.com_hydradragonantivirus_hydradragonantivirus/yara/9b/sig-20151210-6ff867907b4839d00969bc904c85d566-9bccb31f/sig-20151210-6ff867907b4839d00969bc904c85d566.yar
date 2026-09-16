rule sig_20151210_6ff867907b4839d00969bc904c85d566 {
  meta:
    description = "datamaliciousorder - file 20151210_6ff867907b4839d00969bc904c85d566.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c83acc212ce9fc424e8035f673352933460e865465664dae8851cbcd62f5560c"

  strings:
    $s1  = "function gwztDXF(WhLJpCrNPqTgtYRHxDtgMxhURbpAjHGoojfz) {return !isNaN(parseFloat(WhLJpCrNPqTgtYRHxDtgMxhURbpAjHGoojfz)) && isFin" ascii
    $s2  = "function gwztDXF(WhLJpCrNPqTgtYRHxDtgMxhURbpAjHGoojfz) {return !isNaN(parseFloat(WhLJpCrNPqTgtYRHxDtgMxhURbpAjHGoojfz)) && isFin" ascii
    $s3  = " jvbtr;}function wAQpyOQPYgiwZhx(cVHsCRhwZteBfxzhu){eval(cVHsCRhwZteBfxzhu)}" fullword ascii
    $s4  = "+;}} return RUZtFctIsEs}" fullword ascii
    $s5  = "function rAeWKprLVJPanXZhA(zkIGu){RUZtFctIsEs= '';for(EeJHJneEHsu=(-461+461)/906; EeJHJneEHsu < (499+563)/531; EeJHJneEHsu++) {L" ascii
    $s6  = "yOtuCcHg[EeJHJneEHsu]=(-665+665)/825; while(true) { if(LyOtuCcHg[EeJHJneEHsu] > zkIGu[EeJHJneEHsu].length-(737+191)/928) { break" ascii
    $s7  = "function vqyPq(OpqCNrRCzjb,oUUemPfwlsDoV,nrudxdHd){uTbn=parseInt(OpqCNrRCzjb,oUUemPfwlsDoV);jvbtr=uTbn.toString(nrudxdHd);return" ascii
    $s8  = "function vqyPq(OpqCNrRCzjb,oUUemPfwlsDoV,nrudxdHd){uTbn=parseInt(OpqCNrRCzjb,oUUemPfwlsDoV);jvbtr=uTbn.toString(nrudxdHd);return" ascii
    $s9  = "gGUIAgJ=(-907+907)/608;while(true){if(gGUIAgJ>=(58399+609)/461){break;}QtFVjuEVMJEsu[gGUIAgJ]=String.fromCharCode(gGUIAgJ);gGUIA" ascii
    $s10 = "gGUIAgJ=(-907+907)/608;while(true){if(gGUIAgJ>=(58399+609)/461){break;}QtFVjuEVMJEsu[gGUIAgJ]=String.fromCharCode(gGUIAgJ);gGUIA" ascii
    $s11 = "function gJJWzibiqYk(jrXfaMbm,slkGEp){return jrXfaMbm.split(slkGEp)}" fullword ascii
    $s12 = "function rAeWKprLVJPanXZhA(zkIGu){RUZtFctIsEs= '';for(EeJHJneEHsu=(-461+461)/906; EeJHJneEHsu < (499+563)/531; EeJHJneEHsu++) {L" ascii
    $s13 = "function QsaxjKuCqhlBcaLoaYBXnZxHVbFsstZTUpWNEkrMGyzmJAPyQMUbhM(nRQRoUNUQbTIV,IXghyeblOpftMe){ return QtFVjuEVMJEsu[vqyPq(nRQRoU" ascii
    $s14 = "function QsaxjKuCqhlBcaLoaYBXnZxHVbFsstZTUpWNEkrMGyzmJAPyQMUbhM(nRQRoUNUQbTIV,IXghyeblOpftMe){ return QtFVjuEVMJEsu[vqyPq(nRQRoU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}