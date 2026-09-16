rule sig_20151215_b1e9909375429d648aab8e259e453f57 {
  meta:
    description = "datamaliciousorder - file 20151215_b1e9909375429d648aab8e259e453f57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85a8a6d9087eaafb8ac2a49c8bd6f426a72626ec3655cdb950b56e59d0fab780"

  strings:
    $s1  = "ath.pow(Math.cos(586), 2) - 1)); while(true) { if(zEosXDuDd[lfMbycFHNJh] > EcOmD[lfMbycFHNJh].length-(160+487)/647) { break; } i" ascii
    $s2  = "ath.cos(731), 2) - 1)));} zEosXDuDd[lfMbycFHNJh]++;}} return mbySkQpWtcs}" fullword ascii
    $s3  = "function pApkFYLJfpRBrLyHk(EcOmD){mbySkQpWtcs= L[1815];for(lfMbycFHNJh=Math.round((Math.pow(Math.sin(111), 2) + Math.pow(Math.co" ascii
    $s4  = "function pApkFYLJfpRBrLyHk(EcOmD){mbySkQpWtcs= L[1815];for(lfMbycFHNJh=Math.round((Math.pow(Math.sin(111), 2) + Math.pow(Math.co" ascii
    $s5  = "function I(eGicvULdWqSF,gINreAGyUMVhHc){eGicvULdWqSF.push(gINreAGyUMVhHc);}function s2(OVbykFcSSRIjArEC){if(CrPpLfJ(OVbykFcSSRIj" ascii
    $s6  = "ArEC)) {return (String.fromCharCode(OVbykFcSSRIjArEC) + String.fromCharCode((43504+939)/907));}}" fullword ascii
    $s7  = "function CrPpLfJ(AjemIkWTiIJstkmAXookogufzdrEpfUjxKYR) {return !isNaN(parseFloat(AjemIkWTiIJstkmAXookogufzdrEpfUjxKYR)) && isFin" ascii
    $s8  = "function CrPpLfJ(AjemIkWTiIJstkmAXookogufzdrEpfUjxKYR) {return !isNaN(parseFloat(AjemIkWTiIJstkmAXookogufzdrEpfUjxKYR)) && isFin" ascii
    $s9  = "var L=new Array();" fullword ascii
    $s10 = " aLbZN;}function GcWVkHHWNLyMfpf(XPulNyxgyOFdAVieb,xibOUoXTLpytqvFkjagcHnfUllffRrTJQr,uOPtdxtuACjjdYqKnuwzFDXEJrWgdLpFRUI){eval(" ascii
    $s11 = "function CIpKD(zMJSHgIpMTm,NDVuxlPnwlmkb,dCHFZxiP){Stem=parseInt(zMJSHgIpMTm,NDVuxlPnwlmkb);aLbZN=Stem.toString(dCHFZxiP);return" ascii
    $s12 = "function HlLpKbrfzXh(mXzoZekX,jGZwFc){return mXzoZekX.split(jGZwFc)}" fullword ascii
    $s13 = "function CIpKD(zMJSHgIpMTm,NDVuxlPnwlmkb,dCHFZxiP){Stem=parseInt(zMJSHgIpMTm,NDVuxlPnwlmkb);aLbZN=Stem.toString(dCHFZxiP);return" ascii
    $s14 = "function I(eGicvULdWqSF,gINreAGyUMVhHc){eGicvULdWqSF.push(gINreAGyUMVhHc);}function s2(OVbykFcSSRIjArEC){if(CrPpLfJ(OVbykFcSSRIj" ascii
    $s15 = "function GcWVkHHWNLyMfpf(XPulNyxgyOFdAVieb){eval(XPulNyxgyOFdAVieb)}" fullword ascii
    $s16 = "function OJCbQuJTnWmiLNQTBIhSUMMgyaKxMpVphJaPeszZIqsQNEJrEPowUF(azETMlRmwgpSP,DIIbKJwoyJFupV){ return hwLsMBR[FZjsdOzl[CIpKD(azE" ascii
    $s17 = "function OJCbQuJTnWmiLNQTBIhSUMMgyaKxMpVphJaPeszZIqsQNEJrEPowUF(azETMlRmwgpSP,DIIbKJwoyJFupV){ return hwLsMBR[FZjsdOzl[CIpKD(azE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}