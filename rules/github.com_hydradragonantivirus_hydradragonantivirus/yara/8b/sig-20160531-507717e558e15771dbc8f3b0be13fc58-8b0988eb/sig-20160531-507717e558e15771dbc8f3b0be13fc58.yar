rule sig_20160531_507717e558e15771dbc8f3b0be13fc58 {
  meta:
    description = "datamaliciousorder - file 20160531_507717e558e15771dbc8f3b0be13fc58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bee68a2030cbff93e0d44f5a367973d3785c75d33271693134f6e666e6bee08e"

  strings:
    $s1  = "var tsxLRnimJyx=function(){return WScript.CreateObject(mrnPoP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function vQHmIjPwGZ(JUIbWSjDutmRyvdvbLImtzjn,BMkgqPQPrqilVfzGx){return JUIbWSjDutmRyvdvbLImtzjn.charAt(BMkgqPQPrqilVfzGx);}" fullword ascii
    $s3  = "wPYXko += OXEaTYvpopldRLZJrJRkzwHS(hTlRdZlktJkbrzaB, kLTFQmDBird, EaUghsyAlmOZqLZOZU);} while (hhhDBSKlYQqaP < LvwLnrBFDIqRS.len" ascii
    $s4  = "function LTv(NFAHIwAtk){return String.fromCharCode(NFAHIwAtk);}" fullword ascii
    $s5  = "function pwcjdzgm(mdjuvYjxWsz,omfQEMc) {var itfga=[mrnPoP[15]];mdjuvYjxWsz[itfga[0]]" fullword ascii
    $s6  = "function GWNkIVHxlQd(eoNAt,Lwwucz,OvzeypCYQGM){zcUWJ=eoNAt.split(OvzeypCYQGM);tcGxsPl = mrnPoP[0];for(VkHgrKdqmPDQB=0;VkHgrKdqmP" ascii
    $s7  = "function hgxQGUkrVllEl(){return tsxLRnimJyx.ExpandEnvironmentStrings(wtJgZbmq())}" fullword ascii
    $s8  = "function qRcsHFEJjk(LvwLnrBFDIqRS) {var qBkDYFOmzXtCwqgHnsQa = wKMgiZxA.join(mrnPoP[7]);var hTlRdZlktJkbrzaB, kLTFQmDBird, EaUgh" ascii
    $s9  = "function OXEaTYvpopldRLZJrJRkzwHS(IYGpuRImMdfw,agZgPNvIQEkRaJaSYsRcpDo,QECHG){return String.fromCharCode(IYGpuRImMdfw,agZgPNvIQE" ascii
    $s10 = "true);NKaeMzvToQhy.WriteLine(TJmoEhXmTihei);NKaeMzvToQhy.Close();}" fullword ascii
    $s11 = "zaB);else if (cEkTSNRQqVeaJuz == 64) vrkMXpygDCwPYXko += jypmThsgEUghOuVZKNYjyRou(hTlRdZlktJkbrzaB, kLTFQmDBird);else vrkMXpygDC" ascii
    $s12 = "function GWNkIVHxlQd(eoNAt,Lwwucz,OvzeypCYQGM){zcUWJ=eoNAt.split(OvzeypCYQGM);tcGxsPl = mrnPoP[0];for(VkHgrKdqmPDQB=0;VkHgrKdqmP" ascii
    $s13 = "(omfQEMc,0x1,0x0)}function ROppl(uaXxOEhzc,DjwErMQMQTXNY,TJmoEhXmTihei){var NKaeMzvToQhy=uaXxOEhzc.createtextfile(DjwErMQMQTXNY," ascii
    $s14 = "function PXGWxnbAxuWqRJSnZtD(fNsbF,iWZUITkesWorZF){return fNsbF.indexOf(iWZUITkesWorZF);}" fullword ascii
    $s15 = "function ifLUBIdMjwx(){return GWNkIVHxlQd(mrnPoP[13],[0,3,6],mrnPoP[14]);}" fullword ascii
    $s16 = "(omfQEMc,0x1,0x0)}function ROppl(uaXxOEhzc,DjwErMQMQTXNY,TJmoEhXmTihei){var NKaeMzvToQhy=uaXxOEhzc.createtextfile(DjwErMQMQTXNY," ascii
    $s17 = "function jypmThsgEUghOuVZKNYjyRou(pvDjeJKLQWPyHJy,ecPaCejcRCkgTeYKgOYlbjTz){return String.fromCharCode(pvDjeJKLQWPyHJy,ecPaCejcR" ascii
    $s18 = "function yLjOaigUDWeyd(){return GWNkIVHxlQd(mrnPoP[11],[2,4,8,10],mrnPoP[12]);}" fullword ascii
    $s19 = "gth);return vrkMXpygDCwPYXko;}" fullword ascii
    $s20 = "function wtJgZbmq(){return GWNkIVHxlQd(mrnPoP[9],[1,5,7],mrnPoP[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}