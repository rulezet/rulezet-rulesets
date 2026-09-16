rule sig_20160520_94cf70fb5863903b95404620131e239a {
  meta:
    description = "datamaliciousorder - file 20160520_94cf70fb5863903b95404620131e239a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a6e06b762a308758d963abdc636dd5859407b27698ee4f2e906c88f559fcfcf"

  strings:
    $s1  = "function DtenYtft(FLBCJ) {var nrtXpYYE=IWmuPygbJPntwvSkMYyY[2];for(var KwVrQ=0;KwVrQ<FLBCJ;KwVrQ++){ipvzh+=nrtXpYYE.charAt(Math." ascii
    $s2  = "function DtenYtft(FLBCJ) {var nrtXpYYE=IWmuPygbJPntwvSkMYyY[2];for(var KwVrQ=0;KwVrQ<FLBCJ;KwVrQ++){ipvzh+=nrtXpYYE.charAt(Math." ascii
    $s3  = "function MtiAWP(dwXSHv){return dwXSHv.ExpandEnvironmentStrings(IWmuPygbJPntwvSkMYyY[10])}" fullword ascii
    $s4  = "function Zupiidv() {var mWey=100000;var TuIsZh = 100;return Math.random()*(mWey-TuIsZh)+TuIsZh;}" fullword ascii
    $s5  = "function WuHLk(OBkLARNJ,uAYQQb,WrFsmXfYa){jNHtv=OBkLARNJ.split(WrFsmXfYa);BdRTlFL = IWmuPygbJPntwvSkMYyY[13];for(VhQPVeuL=0;VhQP" ascii
    $s6  = "function jLvpR(akEhMSUW,WZWDa,KWSYDEjnJh){akEhMSUW.open();akEhMSUW.type = 1;akEhMSUW.write(WZWDa);akEhMSUW.position = 0;akEhMSUW" ascii
    $s7  = "function WuHLk(OBkLARNJ,uAYQQb,WrFsmXfYa){jNHtv=OBkLARNJ.split(WrFsmXfYa);BdRTlFL = IWmuPygbJPntwvSkMYyY[13];for(VhQPVeuL=0;VhQP" ascii
    $s8  = "function jLvpR(akEhMSUW,WZWDa,KWSYDEjnJh){akEhMSUW.open();akEhMSUW.type = 1;akEhMSUW.write(WZWDa);akEhMSUW.position = 0;akEhMSUW" ascii
    $s9  = "function tTIp(OnDplu,bQeNffi){pvUR = IWmuPygbJPntwvSkMYyY[11].split(IWmuPygbJPntwvSkMYyY[12]);bQeNffi.open(pvUR[0]+pvUR[2]+pvUR[" ascii
    $s10 = "function tTIp(OnDplu,bQeNffi){pvUR = IWmuPygbJPntwvSkMYyY[11].split(IWmuPygbJPntwvSkMYyY[12]);bQeNffi.open(pvUR[0]+pvUR[2]+pvUR[" ascii
    $s11 = "try{nWtlBpNNG(jRtPg[iQyN], Zupiidv() + IWmuPygbJPntwvSkMYyY[9], 1)}catch(e){}; " fullword ascii
    $s12 = "3], OnDplu, false);bQeNffi.send();}" fullword ascii
    $s13 = "floor(Math.random()*nrtXpYYE.length));}return ipvzh;}" fullword ascii
    $s14 = "VeuL<uAYQQb.length;VhQPVeuL++) {BdRTlFL+=jNHtv[uAYQQb[VhQPVeuL]];}return BdRTlFL.substring(3,BdRTlFL.length);}" fullword ascii
    $s15 = "function lDFZC(dwXSHv){return new ActiveXObject(dwXSHv);}" fullword ascii
    $s16 = "function nWtlBpNNG(TevhsIIhZ,tynzCqD,caiIugyG){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}