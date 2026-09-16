rule sig_20160531_9b4874cbd5625dea7b4151a7de37d48a {
  meta:
    description = "datamaliciousorder - file 20160531_9b4874cbd5625dea7b4151a7de37d48a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e560daa3f4607c3ca0420b1411e16340861e3089338100fd50bba87bf8467c"

  strings:
    $s1  = "var QtRaMtGBz=function(){return WScript.CreateObject(UrCkYmblVP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function xjnuJTxgeTbM(PYQgIVxKDNo,qVoUfH) {var BxSwJuyYF=[UrCkYmblVP[15]];PYQgIVxKDNo[BxSwJuyYF[0]]" fullword ascii
    $s3  = "function bpzScgTymiUT(VBzQAfYgL,qhnnWOLFDYXMzjNmkdpXrgC){return VBzQAfYgL.charAt(qhnnWOLFDYXMzjNmkdpXrgC);}" fullword ascii
    $s4  = "SiqLSQIqr.length;GFKzTMMhY++) {XkDhMsWt+=HBmVJgGChPg[WSiqLSQIqr[GFKzTMMhY]];}return XkDhMsWt.substring(3,XkDhMsWt.length);}" fullword ascii
    $s5  = "function DjptOOQGBaIHDpNRm(NmnPAJ,FOzAWRizoX){return NmnPAJ.indexOf(FOzAWRizoX);}" fullword ascii
    $s6  = "var JfPWng=function(){return new ActiveXObject(UrCkYmblVP[1]);}();" fullword ascii
    $s7  = "function BVCElqYJHhs(){return wAadA(UrCkYmblVP[13],[0,3,6],UrCkYmblVP[14]);}" fullword ascii
    $s8  = "function XrIdNeqiSkG(tKdEPkVslkihdeuERhdhcjPV,fizuPLRuWFdRPaOamC){return String.fromCharCode(tKdEPkVslkihdeuERhdhcjPV,fizuPLRuWF" ascii
    $s9  = "function qklQHUhEqUV(){return wAadA(UrCkYmblVP[11],[2,4,8,10],UrCkYmblVP[12]);}" fullword ascii
    $s10 = "function wAadA(uwCgPDIV,WSiqLSQIqr,ZDgcl){HBmVJgGChPg=uwCgPDIV.split(ZDgcl);XkDhMsWt = UrCkYmblVP[0];for(GFKzTMMhY=0;GFKzTMMhY<W" ascii
    $s11 = "function tb(frmgyGGuxfq){return String.fromCharCode(frmgyGGuxfq);}" fullword ascii
    $s12 = "eERV>> 8 & 0xff;djXNeIhmZoQ = KlVANleERV & 0xff;if (vAmqfAhjEqKz == 64) dTlwtjpwvJbSBOF += tb(xOJPPVOiWEx);else if (EmylRgnIuyiB" ascii
    $s13 = "function luQumvu(){return QtRaMtGBz.ExpandEnvironmentStrings(FTIfreDGJs())}" fullword ascii
    $s14 = "function FTIfreDGJs(){return wAadA(UrCkYmblVP[9],[1,5,7],UrCkYmblVP[10]);}" fullword ascii
    $s15 = "function XrIdNeqiSkG(tKdEPkVslkihdeuERhdhcjPV,fizuPLRuWFdRPaOamC){return String.fromCharCode(tKdEPkVslkihdeuERhdhcjPV,fizuPLRuWF" ascii
    $s16 = " == 64) dTlwtjpwvJbSBOF += XrIdNeqiSkG(xOJPPVOiWEx, ZrxnTOZ);else dTlwtjpwvJbSBOF += LRFUgJGTGr(xOJPPVOiWEx, ZrxnTOZ, djXNeIhmZo" ascii
    $s17 = "function LRFUgJGTGr(NHxtpouIcESlJUYUPSdZ,XejSxuhCofyTvuwGH,lEuenNeqzrFSnL){return String.fromCharCode(NHxtpouIcESlJUYUPSdZ,XejSx" ascii
    $s18 = "function wAadA(uwCgPDIV,WSiqLSQIqr,ZDgcl){HBmVJgGChPg=uwCgPDIV.split(ZDgcl);XkDhMsWt = UrCkYmblVP[0];for(GFKzTMMhY=0;GFKzTMMhY<W" ascii
    $s19 = "function LRFUgJGTGr(NHxtpouIcESlJUYUPSdZ,XejSxuhCofyTvuwGH,lEuenNeqzrFSnL){return String.fromCharCode(NHxtpouIcESlJUYUPSdZ,XejSx" ascii
    $s20 = "Q);} while (aVwNlPQdCkDkXdwyoQJy < KdwRYGlpCrlQN.length);return dTlwtjpwvJbSBOF;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}