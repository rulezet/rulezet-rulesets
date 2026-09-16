rule sig_20151216_b6c789e1712232a19186444efa58c1bd {
  meta:
    description = "datamaliciousorder - file 20151216_b6c789e1712232a19186444efa58c1bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6bd8797e7a77647171a99102f50c82960d23af05fa928368880b9f370c24c6"

  strings:
    $s1  = "th.pow(Math.cos(500), 2) - 1)); while(true) { if(VZPNvNVbc[KenTBoshJdq] > xEnwJ[KenTBoshJdq].length-(-328+868)/540) { break; } i" ascii
    $s2  = ") - 1));while(true){if (KenTBoshJdq >= (2162+586)/458){break;}VZPNvNVbc[KenTBoshJdq]=Math.round((Math.pow(Math.sin(500), 2) + Ma" ascii
    $s3  = "ow(Math.cos(270), 2) - 1)));} VZPNvNVbc[KenTBoshJdq]++;}KenTBoshJdq++;} return BoQegjZauvJ}" fullword ascii
    $s4  = "function cdkMucCfXTOzTQzfb(xEnwJ){BoQegjZauvJ= '';KenTBoshJdq=Math.round((Math.pow(Math.sin(949), 2) + Math.pow(Math.cos(949), 2" ascii
    $s5  = "function cdkMucCfXTOzTQzfb(xEnwJ){BoQegjZauvJ= '';KenTBoshJdq=Math.round((Math.pow(Math.sin(949), 2) + Math.pow(Math.cos(949), 2" ascii
    $s6  = "function mtkJXRx(ROcFpSIDCbbOkYdhuJHJGOXXEORMJNfrbbQk) {return !ZaXxcHVHOvH(bgLjzReUggkbrHQ(ROcFpSIDCbbOkYdhuJHJGOXXEORMJNfrbbQk" ascii
    $s7  = "function hJDXhsssaJIMXti(MKwHWjlpOOkWglQSE,KhXAJBIGHSMtmPaPEDFzalulBUnkGwqWGR,ymPlFNRumDuvzBdgbfGXDoARRLJGEIPiDRf){eval(MKwHWjlp" ascii
    $s8  = "function hJDXhsssaJIMXti(MKwHWjlpOOkWglQSE,KhXAJBIGHSMtmPaPEDFzalulBUnkGwqWGR,ymPlFNRumDuvzBdgbfGXDoARRLJGEIPiDRf){eval(MKwHWjlp" ascii
    $s9  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s10 = "function mtkJXRx(ROcFpSIDCbbOkYdhuJHJGOXXEORMJNfrbbQk) {return !ZaXxcHVHOvH(bgLjzReUggkbrHQ(ROcFpSIDCbbOkYdhuJHJGOXXEORMJNfrbbQk" ascii
    $s11 = "function ZaXxcHVHOvH(WEOnIPKOatCYkM) {return isNaN(WEOnIPKOatCYkM);}" fullword ascii
    $s12 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s13 = "function bgLjzReUggkbrHQ(MZqGNHQOJEceWckaWZM) {return parseFloat(MZqGNHQOJEceWckaWZM);}" fullword ascii
    $s14 = "c);return iFBJe;}" fullword ascii
    $s15 = "function R(kQnXEINEuBfaiX,PUCuSoNCyhQTd,fvigYyefxYJ) {kQnXEINEuBfaiX[PUCuSoNCyhQTd]=fvigYyefxYJ;}" fullword ascii
    $s16 = "function H(pRICHlMALhZS,kasFkyFohsdWsm){pRICHlMALhZS.push(kasFkyFohsdWsm);}" fullword ascii
    $s17 = "function emYOsWIBMeHh(kpRFCjnVbdHhr) {return isFinite(kpRFCjnVbdHhr);}" fullword ascii
    $s18 = "function BqNPt(GuQJOnkzvuI,FrpkAzelXqrvV,AtGmKanc){hxjU=pRFHPBUaqSSjBCAap(GuQJOnkzvuI,FrpkAzelXqrvV);iFBJe=hxjU.toString(AtGmKan" ascii
    $s19 = "function kDQWZhorqVhtHAidrHnHLKKiNnZGTVuSnVUnCFLSplQIpOrkHkzqCa(KedUYdSBHUrTM,CgqpSbGlquwakX){ return otQwRKi[SyZQkMXH[BqNPt(Ked" ascii
    $s20 = "function kDQWZhorqVhtHAidrHnHLKKiNnZGTVuSnVUnCFLSplQIpOrkHkzqCa(KedUYdSBHUrTM,CgqpSbGlquwakX){ return otQwRKi[SyZQkMXH[BqNPt(Ked" ascii

  condition:
    uint16(0) == 0x7953 and
    8 of them
}