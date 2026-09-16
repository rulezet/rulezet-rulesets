rule sig_20160530_a62f35c8a733a8180cf064ce0080431e {
  meta:
    description = "datamaliciousorder - file 20160530_a62f35c8a733a8180cf064ce0080431e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20cacb5c3db35079621e07a4832543ca711921f9b91b45645579c7f22a2d57e0"

  strings:
    $s1  = "var vEnlYGs=function(){return WScript.CreateObject(NGfJVteJHFONHgu[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function KfBOjgRhMVthOOSa(JJjiiZLGGzjourKE,qAYnKdjWXvoqc){return JJjiiZLGGzjourKE.charAt(qAYnKdjWXvoqc);}" fullword ascii
    $s3  = "function EZiKOdGvfo(jagOprJjssEhI) {var DNTIzOWVopGkHvFildSo = YyYYw.join(NGfJVteJHFONHgu[7]);var NckYvlI, MarVKQDpBAYdNiywh, QR" ascii
    $s4  = "function EZiKOdGvfo(jagOprJjssEhI) {var DNTIzOWVopGkHvFildSo = YyYYw.join(NGfJVteJHFONHgu[7]);var NckYvlI, MarVKQDpBAYdNiywh, QR" ascii
    $s5  = "rCode(92)+NGfJVteJHFONHgu[5],true);" fullword ascii
    $s6  = "function miLivmmLHks(GPieyIhFGcrVinzWwnQF,ipqljRUEWU){return String.fromCharCode(GPieyIhFGcrVinzWwnQF,ipqljRUEWU);}" fullword ascii
    $s7  = "JHFONHgu[0];for(NbiKvI=0;NbiKvI<KPRFTdFluwTq.length;NbiKvI++) {sWYGkqXxN+=WvnqDxtTx[KPRFTdFluwTq[NbiKvI]];}return sWYGkqXxN.subs" ascii
    $s8  = "var XWiWCyUxCnF = yrZhyrkF.createtextfile(vEnlYGs.ExpandEnvironmentStrings(NGfJVteJHFONHgu[3]+NGfJVteJHFONHgu[4])+String.fromCha" ascii
    $s9  = "function EQuClAPn(){return rTngoLtfyejMOU(NGfJVteJHFONHgu[9],[1,5,7],NGfJVteJHFONHgu[10]);}" fullword ascii
    $s10 = "function cdEqBjWnBaAbNq(){return vEnlYGs.ExpandEnvironmentStrings(EQuClAPn())}" fullword ascii
    $s11 = "function rTngoLtfyejMOU(XjVsQKmLHmMeD,KPRFTdFluwTq,jQskvIuquPHr){WvnqDxtTx=XjVsQKmLHmMeD.split(jQskvIuquPHr);sWYGkqXxN = NGfJVte" ascii
    $s12 = "function SO(rCnyXmnNvWjAEpxImzMzxPeg){return String.fromCharCode(rCnyXmnNvWjAEpxImzMzxPeg);}" fullword ascii
    $s13 = " += SO(NckYvlI);else if (OrOymWRhvtFAbREVyGJmML == 64) ndSxA += miLivmmLHks(NckYvlI, MarVKQDpBAYdNiywh);else ndSxA += XbliEHBjFb" ascii
    $s14 = "function KNUsbXzilrpOuwZLJVvpszB(TOjbIawzUFWw,PBjZjJPNk){return TOjbIawzUFWw.indexOf(PBjZjJPNk);}" fullword ascii
    $s15 = "function XbliEHBjFbpxt(dNhPYb,HyxUoOHpwM,oBAUbyzChjchCr){return String.fromCharCode(dNhPYb,HyxUoOHpwM,oBAUbyzChjchCr);}" fullword ascii
    $s16 = "var yrZhyrkF=function(){return new ActiveXObject(NGfJVteJHFONHgu[1]);}();" fullword ascii
    $s17 = "function rTngoLtfyejMOU(XjVsQKmLHmMeD,KPRFTdFluwTq,jQskvIuquPHr){WvnqDxtTx=XjVsQKmLHmMeD.split(jQskvIuquPHr);sWYGkqXxN = NGfJVte" ascii
    $s18 = "pxt(NckYvlI, MarVKQDpBAYdNiywh, QRAEAEYVATOikKtNnTjpSh);} while (bFmhWSafMhxZX < jagOprJjssEhI.length);return ndSxA;}" fullword ascii
    $s19 = "function qeCyp(){return rTngoLtfyejMOU(NGfJVteJHFONHgu[11],[2,4,8,10],NGfJVteJHFONHgu[12]);}" fullword ascii
    $s20 = "function rocQdqcKjSgh(){return rTngoLtfyejMOU(NGfJVteJHFONHgu[13],[0,3,6],NGfJVteJHFONHgu[14]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}