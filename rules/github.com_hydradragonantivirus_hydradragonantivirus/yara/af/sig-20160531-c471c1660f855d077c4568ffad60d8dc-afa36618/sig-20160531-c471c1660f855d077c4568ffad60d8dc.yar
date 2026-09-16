rule sig_20160531_c471c1660f855d077c4568ffad60d8dc {
  meta:
    description = "datamaliciousorder - file 20160531_c471c1660f855d077c4568ffad60d8dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ebff1cb58a6c7d7ba9c99545497d67468d36c3252b8b78e1f4d75b025593884"

  strings:
    $s1  = "var VErLRVaSrrap=function(){return WScript.CreateObject(SXidXZ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function hrgtAVrGUj(VLZtbjOTMsNtWqX,pYZNjoxwVBLvKJKUiooOo){return VLZtbjOTMsNtWqX.charAt(pYZNjoxwVBLvKJKUiooOo);}" fullword ascii
    $s3  = "function TbtoK(RQZXRl,ZqukOUc){return String.fromCharCode(RQZXRl,ZqukOUc);}" fullword ascii
    $s4  = "function GnyExCvdM(){return VErLRVaSrrap.ExpandEnvironmentStrings(cJnzPyIcDj())}" fullword ascii
    $s5  = "function iBwjpXUnMGWuRY(ZYFllsGeV,YlYJT) {var rRLnOz=[SXidXZ[15]];ZYFllsGeV[rRLnOz[0]]" fullword ascii
    $s6  = "function cJnzPyIcDj(){return HqDRTjret(SXidXZ[9],[1,5,7],SXidXZ[10]);}" fullword ascii
    $s7  = "function KfrQbLBcdOc(){return HqDRTjret(SXidXZ[11],[2,4,8,10],SXidXZ[12]);}" fullword ascii
    $s8  = "function HqDRTjret(XavIptjzo,ZpLaOGQBUPkIn,oXMizkkcej){zvXnZi=XavIptjzo.split(oXMizkkcej);QRHOzgwtaQWR = SXidXZ[0];for(xWZcBoxb=" ascii
    $s9  = "0;xWZcBoxb<ZpLaOGQBUPkIn.length;xWZcBoxb++) {QRHOzgwtaQWR+=zvXnZi[ZpLaOGQBUPkIn[xWZcBoxb]];}return QRHOzgwtaQWR.substring(3,QRHO" ascii
    $s10 = "function bObZhExMxm(){return HqDRTjret(SXidXZ[13],[0,3,6],SXidXZ[14]);}" fullword ascii
    $s11 = ";} while (WrSgVmDrHJc < WYVEnGMSNotKm.length);return WSoLXPvKIRupbCNa;}" fullword ascii
    $s12 = "var sOqSyAvnOgX=function(){return new ActiveXObject(SXidXZ[1]);}();" fullword ascii
    $s13 = "push(\"U\");GWjoThmqeeHz.push(\"V\");GWjoThmqeeHz.push(\"W\");GWjoThmqeeHz.push(\"X\");GWjoThmqeeHz.push(\"Y\");GWjoThmqeeHz.pus" ascii
    $s14 = "function YEndAYYBkWoizAIaxlwDG(iEwKABGABHVAZdZBMxeRhjHe,NmevItpw){return iEwKABGABHVAZdZBMxeRhjHe.indexOf(NmevItpw);}" fullword ascii
    $s15 = "function IDFdnfcPEj(WYVEnGMSNotKm) {var ToFyUkoLvZYXdSj = GWjoThmqeeHz.join(SXidXZ[7]);var EDWoMShNkcyGgDBaUgV, WeTuJzBDLkskKbeP" ascii
    $s16 = "function IDFdnfcPEj(WYVEnGMSNotKm) {var ToFyUkoLvZYXdSj = GWjoThmqeeHz.join(SXidXZ[7]);var EDWoMShNkcyGgDBaUgV, WeTuJzBDLkskKbeP" ascii
    $s17 = "Na += TbtoK(EDWoMShNkcyGgDBaUgV, WeTuJzBDLkskKbeP);else WSoLXPvKIRupbCNa += OGcjBl(EDWoMShNkcyGgDBaUgV, WeTuJzBDLkskKbeP, SYXcX)" ascii
    $s18 = "function OGcjBl(bEZxkR,mziBPooYznRLka,onaSMZsaVQJXZDog){return String.fromCharCode(bEZxkR,mziBPooYznRLka,onaSMZsaVQJXZDog);}" fullword ascii
    $s19 = "function HqDRTjret(XavIptjzo,ZpLaOGQBUPkIn,oXMizkkcej){zvXnZi=XavIptjzo.split(oXMizkkcej);QRHOzgwtaQWR = SXidXZ[0];for(xWZcBoxb=" ascii
    $s20 = " 0xff;if (IubmMxhXMGXOE == 64) WSoLXPvKIRupbCNa += ya(EDWoMShNkcyGgDBaUgV);else if (OwcrhgZoKYmOAiNRBqudRo == 64) WSoLXPvKIRupbC" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}