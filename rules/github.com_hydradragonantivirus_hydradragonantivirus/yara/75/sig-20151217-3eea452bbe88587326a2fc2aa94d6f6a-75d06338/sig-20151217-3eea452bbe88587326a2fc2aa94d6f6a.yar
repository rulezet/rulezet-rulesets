rule sig_20151217_3eea452bbe88587326a2fc2aa94d6f6a {
  meta:
    description = "datamaliciousorder - file 20151217_3eea452bbe88587326a2fc2aa94d6f6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f94f652669b184b6ac654f01ab324b11c35992c551a4ab353e0020354e1088a1"

  strings:
    $s1  = "(Math.cos(764), 2) - 1)));} RCRzFsnYM[ngeuJLiprrP]++;}ngeuJLiprrP++;} return dviLlrFmvpt}" fullword ascii
    $s2  = ".pow(Math.cos(477), 2) - 1)); while(true) { if(RCRzFsnYM[ngeuJLiprrP] > VwWtF[ngeuJLiprrP].length-(65+667)/732) { break; } if (a" ascii
    $s3  = "function tqcsRuZDDpBYIczri(VwWtF){dviLlrFmvpt= '';ngeuJLiprrP=Math.round((Math.pow(Math.sin(34), 2) + Math.pow(Math.cos(34), 2) " ascii
    $s4  = "function tqcsRuZDDpBYIczri(VwWtF){dviLlrFmvpt= '';ngeuJLiprrP=Math.round((Math.pow(Math.sin(34), 2) + Math.pow(Math.cos(34), 2) " ascii
    $s5  = "- 1));while(true){if (ngeuJLiprrP >= (3020+772)/632){break;}RCRzFsnYM[ngeuJLiprrP]=Math.round((Math.pow(Math.sin(477), 2) + Math" ascii
    $s6  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s7  = "function KajMfpfxwaZ(hKttjPcUgadPEK) {return isNaN(hKttjPcUgadPEK);}" fullword ascii
    $s8  = "function KqEfrySUNNWMlRpXESIuviTzQdnIigjDaFUKezVHRnNsEJdfExhFWY(HEemjOojTuHiY,TPlzaMCkHiKZYZ){ return zZSvpqM[EaqJmouY[ZMKon(HEe" ascii
    $s9  = "function EaXatAVJQAHkAer(RQdUjBTwSncjiOHWq,JcISOxrkrPLpgeiQIkhmtsaEoiWmUBjrIS,PiTpPFAHsdJsxnHlUmIRLvKzifFfJYtHESR){eval(RQdUjBTw" ascii
    $s10 = "function ZMKon(WaKkpmqNGJP,ugyDzWYIAuRTy,vwAJjgWH){dGKL=LfPszKfZZPBidhOGm(WaKkpmqNGJP,ugyDzWYIAuRTy);dKhjl=dGKL.toString(vwAJjgW" ascii
    $s11 = "function LfPszKfZZPBidhOGm(omUbtqeAIu,mZqCwmDPJG) {return parseInt(omUbtqeAIu,mZqCwmDPJG);}" fullword ascii
    $s12 = "function IAWeflMwsDfi(OLvrGkZLfqraC) {return isFinite(OLvrGkZLfqraC);}" fullword ascii
    $s13 = "function v(OQlmUOwFLuja,tabAsMSwDpjwSn){OQlmUOwFLuja.push(tabAsMSwDpjwSn);}" fullword ascii
    $s14 = "function ZMKon(WaKkpmqNGJP,ugyDzWYIAuRTy,vwAJjgWH){dGKL=LfPszKfZZPBidhOGm(WaKkpmqNGJP,ugyDzWYIAuRTy);dKhjl=dGKL.toString(vwAJjgW" ascii
    $s15 = "H);return dKhjl;}" fullword ascii
    $s16 = "function KqEfrySUNNWMlRpXESIuviTzQdnIigjDaFUKezVHRnNsEJdfExhFWY(HEemjOojTuHiY,TPlzaMCkHiKZYZ){ return zZSvpqM[EaqJmouY[ZMKon(HEe" ascii
    $s17 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s18 = "function AbSaLjRxbaFMkDx(mkWZADZKuTRCGWamXcG) {return parseFloat(mkWZADZKuTRCGWamXcG);}" fullword ascii
    $s19 = "function EaXatAVJQAHkAer(RQdUjBTwSncjiOHWq,JcISOxrkrPLpgeiQIkhmtsaEoiWmUBjrIS,PiTpPFAHsdJsxnHlUmIRLvKzifFfJYtHESR){eval(RQdUjBTw" ascii
    $s20 = "function s(sNHFZaEdINBDLA,wtWqjpmvvUyyS,hkSPAZazMDc) {sNHFZaEdINBDLA[wtWqjpmvvUyyS]=hkSPAZazMDc;}" fullword ascii

  condition:
    uint16(0) == 0x6145 and
    8 of them
}