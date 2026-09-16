rule sig_20160531_748c9e8e3169cebe230b9a168efb8031 {
  meta:
    description = "datamaliciousorder - file 20160531_748c9e8e3169cebe230b9a168efb8031.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bda9620c11d17f6b18ed92412f02d817671e95e718395aa088eefa601a9f7881"

  strings:
    $s1  = "var eftJpXNGY=function(){return WScript.CreateObject(euXgIAZ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function IKxIu(krptapFcfa,eyikToFmfn){return krptapFcfa.charAt(eyikToFmfn);}" fullword ascii
    $s3  = "function hHxkrRidiXAruS(WGiPJIkQWEGgg) {var EzggaMrz = bpjCq.join(euXgIAZ[7]);var fiyzMtQAnKAakbrVznJVzy, IlCZMWGHcbqFaP, uXZZWK" ascii
    $s4  = "brVznJVzy, IlCZMWGHcbqFaP, uXZZWKkCrUNGLz);} while (tnBPjCKbXRlrjirOqyWP < WGiPJIkQWEGgg.length);return vIJSGbWjyzJbqVVNfRG;}" fullword ascii
    $s5  = "function hHxkrRidiXAruS(WGiPJIkQWEGgg) {var EzggaMrz = bpjCq.join(euXgIAZ[7]);var fiyzMtQAnKAakbrVznJVzy, IlCZMWGHcbqFaP, uXZZWK" ascii
    $s6  = "fRG += QAcVgbzoZOYolCJQkq(fiyzMtQAnKAakbrVznJVzy, IlCZMWGHcbqFaP);else vIJSGbWjyzJbqVVNfRG += QknJVZFeGXawgtoCUBxw(fiyzMtQAnKAak" ascii
    $s7  = "function ebTGzMtpLPvk(QvEtL,eCwzaCWeNUdV) {var SYcyKU=[euXgIAZ[15]];QvEtL[SYcyKU[0]]" fullword ascii
    $s8  = "function QAcVgbzoZOYolCJQkq(eJZLyMMW,MuKoAxAokUaEtpuRZLBWA){return String.fromCharCode(eJZLyMMW,MuKoAxAokUaEtpuRZLBWA);}" fullword ascii
    $s9  = "function IvkWrB(){return TuktvYt(euXgIAZ[13],[0,3,6],euXgIAZ[14]);}" fullword ascii
    $s10 = "(eCwzaCWeNUdV,0x1,0x0)}function wwQhF(jTVAWRQ,MNZpCxACcVjI,sYHtkOhYoOGM){var KyKmsYrChBtPbs=jTVAWRQ.createtextfile(MNZpCxACcVjI," ascii
    $s11 = "function ALWjsecFW(){return TuktvYt(euXgIAZ[9],[1,5,7],euXgIAZ[10]);}" fullword ascii
    $s12 = "function OSjynB(){return eftJpXNGY.ExpandEnvironmentStrings(ALWjsecFW())}" fullword ascii
    $s13 = "function QknJVZFeGXawgtoCUBxw(CUEIa,xlKXWcYWX,YkFmAqIv){return String.fromCharCode(CUEIa,xlKXWcYWX,YkFmAqIv);}" fullword ascii
    $s14 = "function FxmldnofREhYjUmyvUBO(gcqkgZaupuUMJhIpxzMuBEEG,dJHVwbOL){return gcqkgZaupuUMJhIpxzMuBEEG.indexOf(dJHVwbOL);}" fullword ascii
    $s15 = "(eCwzaCWeNUdV,0x1,0x0)}function wwQhF(jTVAWRQ,MNZpCxACcVjI,sYHtkOhYoOGM){var KyKmsYrChBtPbs=jTVAWRQ.createtextfile(MNZpCxACcVjI," ascii
    $s16 = "var hfnETbq=function(){return new ActiveXObject(euXgIAZ[1]);}();" fullword ascii
    $s17 = "function em(oBisdfcqihObzWXayHeBJy){return String.fromCharCode(oBisdfcqihObzWXayHeBJy);}" fullword ascii
    $s18 = "XFzAt & 0xff;if (QFGtzHpSbtPYpkA == 64) vIJSGbWjyzJbqVVNfRG += em(fiyzMtQAnKAakbrVznJVzy);else if (rHtVe == 64) vIJSGbWjyzJbqVVN" ascii
    $s19 = "true);KyKmsYrChBtPbs.WriteLine(sYHtkOhYoOGM);KyKmsYrChBtPbs.Close();}" fullword ascii
    $s20 = "function TuktvYt(IAPiCVBsb,uJyeNXnA,wuFygj){LsWCAMoP=IAPiCVBsb.split(wuFygj);Osocxy = euXgIAZ[0];for(YvOZNh=0;YvOZNh<uJyeNXnA.le" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}