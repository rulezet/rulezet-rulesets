rule sig_20160531_f6da641b2c33985417aa66e477a57fa8 {
  meta:
    description = "datamaliciousorder - file 20160531_f6da641b2c33985417aa66e477a57fa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a530f54a0a63380de046b40bc055d9fecf35025478e484892caceb171e441e2"

  strings:
    $s1  = "var AseCQlEEnww=function(){return WScript.CreateObject(OeIyCjsGGzxNLvzWhmmIlwXK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function iayPknue(VlHwm,hcQWHEd){return VlHwm.charAt(hcQWHEd);}" fullword ascii
    $s3  = "var FCUgv=function(){return new ActiveXObject(OeIyCjsGGzxNLvzWhmmIlwXK[1]);}();" fullword ascii
    $s4  = "tpcNKUeL,true);ZHLJynUPsXKXGp.WriteLine(ASLducJRps);ZHLJynUPsXKXGp.Close();}" fullword ascii
    $s5  = "r(vyJrYcRfZ=0;vyJrYcRfZ<awsCOXQoZbnEE.length;vyJrYcRfZ++) {yQKLIlqFhH+=xIWGkfDmkgi[awsCOXQoZbnEE[vyJrYcRfZ]];}return yQKLIlqFhH." ascii
    $s6  = "function EppXR(jTXuFL,awsCOXQoZbnEE,jBJdZcvGGM){xIWGkfDmkgi=jTXuFL.split(jBJdZcvGGM);yQKLIlqFhH = OeIyCjsGGzxNLvzWhmmIlwXK[0];fo" ascii
    $s7  = "function aCwnK(){return AseCQlEEnww.ExpandEnvironmentStrings(xuCvG())}" fullword ascii
    $s8  = "function QQyHms(PrAYgvTWb,fJgnNwJAvSFgDtRjC){return PrAYgvTWb.indexOf(fJgnNwJAvSFgDtRjC);}" fullword ascii
    $s9  = "function aZvyXM(NbBZNpoltNPLp) {var GKoMXicXXMdNmoOr = AATFnFvFxsJwEHNrLYt.join(OeIyCjsGGzxNLvzWhmmIlwXK[7]);var UNsgT, DzZeWfzH" ascii
    $s10 = "(TaVnjBIPth,0x1,0x0)}function xTMXORlVQH(rpOWhMbBayyPu,NItpcNKUeL,ASLducJRps){var ZHLJynUPsXKXGp=rpOWhMbBayyPu.createtextfile(NI" ascii
    $s11 = "function NWtCOKrhCtELo(DKCUqZULGanQwY,TaVnjBIPth) {var AyxAmb=[OeIyCjsGGzxNLvzWhmmIlwXK[15]];DKCUqZULGanQwY[AyxAmb[0]]" fullword ascii
    $s12 = "function xuCvG(){return EppXR(OeIyCjsGGzxNLvzWhmmIlwXK[9],[1,5,7],OeIyCjsGGzxNLvzWhmmIlwXK[10]);}" fullword ascii
    $s13 = "NHAGJQq);else RKQWkWnnlPx += ECJkTtNNB(UNsgT, DzZeWfzHDXUfbZaPVNHAGJQq, yFkEt);} while (IcBKgiO < NbBZNpoltNPLp.length);return R" ascii
    $s14 = "function ECJkTtNNB(RyDhNFNaBxvlaY,rRDDQeCDVKlyoVUZ,FZWmWSkHPS){return String.fromCharCode(RyDhNFNaBxvlaY,rRDDQeCDVKlyoVUZ,FZWmWS" ascii
    $s15 = "== 64) RKQWkWnnlPx += gM(UNsgT);else if (OCIRtpqaGDceiQeJgdOGbnI == 64) RKQWkWnnlPx += mMuKHGyCDeNBvvKV(UNsgT, DzZeWfzHDXUfbZaPV" ascii
    $s16 = "function mMuKHGyCDeNBvvKV(qOWgZdXmTgcEWgEXxYjPjQ,QbBKjc){return String.fromCharCode(qOWgZdXmTgcEWgEXxYjPjQ,QbBKjc);}" fullword ascii
    $s17 = "function EppXR(jTXuFL,awsCOXQoZbnEE,jBJdZcvGGM){xIWGkfDmkgi=jTXuFL.split(jBJdZcvGGM);yQKLIlqFhH = OeIyCjsGGzxNLvzWhmmIlwXK[0];fo" ascii
    $s18 = "function UaORDx(){return EppXR(OeIyCjsGGzxNLvzWhmmIlwXK[13],[0,3,6],OeIyCjsGGzxNLvzWhmmIlwXK[14]);}" fullword ascii
    $s19 = "function aZvyXM(NbBZNpoltNPLp) {var GKoMXicXXMdNmoOr = AATFnFvFxsJwEHNrLYt.join(OeIyCjsGGzxNLvzWhmmIlwXK[7]);var UNsgT, DzZeWfzH" ascii
    $s20 = "function ECJkTtNNB(RyDhNFNaBxvlaY,rRDDQeCDVKlyoVUZ,FZWmWSkHPS){return String.fromCharCode(RyDhNFNaBxvlaY,rRDDQeCDVKlyoVUZ,FZWmWS" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}