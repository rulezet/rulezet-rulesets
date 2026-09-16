rule sig_20160531_b315038290b90280dd06e63cc0447626 {
  meta:
    description = "datamaliciousorder - file 20160531_b315038290b90280dd06e63cc0447626.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e683360d14c655f4f969bc4e9925bacd625b53359089f2aee894be729243a2"

  strings:
    $s1  = "function vqzGqqZpUpoDKAKArBjrcVEq(QowUAqYFiLd,ZQtZnNKbdwbgYcOMm){return QowUAqYFiLd.charAt(ZQtZnNKbdwbgYcOMm);}" fullword ascii
    $s2  = "var zpqTMLiuj=function(){return WScript.CreateObject(WbqyhRGUMyBchlxj[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "function dFlDRhBLoImFQu(OzNUAkpYJR,qCXam,FZuQU){kGHKhmjtbC=OzNUAkpYJR.split(FZuQU);czypK = WbqyhRGUMyBchlxj[0];for(eXuncXbpQ=0;e" ascii
    $s4  = ";} while (grlcCHrAReSSM < msilYtWWKRQbL.length);return ZrtvaLajsrjxQTiZZx;}" fullword ascii
    $s5  = "function IpAAOwRpldmkKMLfRXyseTaq(aCFouJHBWJARKSDowVsJgnmY,jlpUowDwAKprsMFbbOameiGI,eyfmEEiUduEfcOJviZutAiDH){return String.from" ascii
    $s6  = "function IpAAOwRpldmkKMLfRXyseTaq(aCFouJHBWJARKSDowVsJgnmY,jlpUowDwAKprsMFbbOameiGI,eyfmEEiUduEfcOJviZutAiDH){return String.from" ascii
    $s7  = "var yvchPC=function(){return new ActiveXObject(WbqyhRGUMyBchlxj[1]);}();" fullword ascii
    $s8  = "function dFlDRhBLoImFQu(OzNUAkpYJR,qCXam,FZuQU){kGHKhmjtbC=OzNUAkpYJR.split(FZuQU);czypK = WbqyhRGUMyBchlxj[0];for(eXuncXbpQ=0;e" ascii
    $s9  = "function uSeujMSpA(){return dFlDRhBLoImFQu(WbqyhRGUMyBchlxj[9],[1,5,7],WbqyhRGUMyBchlxj[10]);}" fullword ascii
    $s10 = "function Os(VubFHidQHCOUa){return String.fromCharCode(VubFHidQHCOUa);}" fullword ascii
    $s11 = "function xLmsbsIpET(FeeGq,DQYzBN) {var qznLy=[WbqyhRGUMyBchlxj[15]];FeeGq[qznLy[0]]" fullword ascii
    $s12 = "function nkjpJYEpKilfbMH(YLOWNCXXzyaHCg,FWQXPh){return String.fromCharCode(YLOWNCXXzyaHCg,FWQXPh);}" fullword ascii
    $s13 = "(DQYzBN,0x1,0x0)}function UllJksO(IWpLTH,tgpMtZTdVBNV,GRFwCq){var eRURsMeivb=IWpLTH.createtextfile(tgpMtZTdVBNV,true);eRURsMeivb" ascii
    $s14 = "XuncXbpQ<qCXam.length;eXuncXbpQ++) {czypK+=kGHKhmjtbC[qCXam[eXuncXbpQ]];}return czypK.substring(3,czypK.length);}" fullword ascii
    $s15 = "function xvxRD(){return dFlDRhBLoImFQu(WbqyhRGUMyBchlxj[11],[2,4,8,10],WbqyhRGUMyBchlxj[12]);}" fullword ascii
    $s16 = "function IEaZGDPd(){return dFlDRhBLoImFQu(WbqyhRGUMyBchlxj[13],[0,3,6],WbqyhRGUMyBchlxj[14]);}" fullword ascii
    $s17 = "function nKvLyVpROCqwna(pKSpQOIIRviAfnCskpZaHl,sCKFzWO){return pKSpQOIIRviAfnCskpZaHl.indexOf(sCKFzWO);}" fullword ascii
    $s18 = "function pOTaKcfnmdR(msilYtWWKRQbL) {var TRnKLPtkxfboffN = kWEmgKIGVkZ.join(WbqyhRGUMyBchlxj[7]);var zkEpYGVbXSVzajrrTbhrhpge, m" ascii
    $s19 = "(DQYzBN,0x1,0x0)}function UllJksO(IWpLTH,tgpMtZTdVBNV,GRFwCq){var eRURsMeivb=IWpLTH.createtextfile(tgpMtZTdVBNV,true);eRURsMeivb" ascii
    $s20 = "function RaNdPABeUEsWJT(){return zpqTMLiuj.ExpandEnvironmentStrings(uSeujMSpA())}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}