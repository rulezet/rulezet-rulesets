rule sig_20160531_1cc5a8bb2bda56452dfa1ab02a75fad1 {
  meta:
    description = "datamaliciousorder - file 20160531_1cc5a8bb2bda56452dfa1ab02a75fad1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f935849cc5ae9e989a3aa1834eecb2c08bcf80478ad91047c37c2483b26ad96f"

  strings:
    $s1  = "var kKmgxKj=function(){return WScript.CreateObject(mJNhTunUIlSo[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function pJwJEP(WJbjoKDqBogQlziTS,pVmSekfdNo){return WJbjoKDqBogQlziTS.charAt(pVmSekfdNo);}" fullword ascii
    $s3  = "(GSPBWedQBN,0x1,0x0)}function osryjKENUNGG(sdYxqLkfGx,SYksikqOkn,iYKYOw){var nGYybF=sdYxqLkfGx.createtextfile(SYksikqOkn,true);n" ascii
    $s4  = "function uucjX(){return QAefDTcOH(mJNhTunUIlSo[13],[0,3,6],mJNhTunUIlSo[14]);}" fullword ascii
    $s5  = "function bdnmMKbwaOxFZ(){return QAefDTcOH(mJNhTunUIlSo[11],[2,4,8,10],mJNhTunUIlSo[12]);}" fullword ascii
    $s6  = "function vWBwjKieYALDURrOR(mCezB,omZpjvISJBrRpEgf,VXPIxwEccffqRLzEDSvzcQ){return String.fromCharCode(mCezB,omZpjvISJBrRpEgf,VXPI" ascii
    $s7  = "function yJLEtCiLUG(slDkVpBG,TOViegW){return slDkVpBG.indexOf(TOViegW);}" fullword ascii
    $s8  = "rDwdnEDl = ICzGdOeXGfGQrbgp & 0xff;if (YGvLaFitFevbkaLKMPhVf == 64) ndHGRpYfsFZXMXnPMPRhd += aW(zmqhGFZPfkiIxiSnYER);else if (NX" ascii
    $s9  = "OR(zmqhGFZPfkiIxiSnYER, qFtbkaIixoc, peIfTXKdaOzhUrDwdnEDl);} while (JwVJoxemBMf < sMxqHRExEZTjX.length);return ndHGRpYfsFZXMXnP" ascii
    $s10 = "function wOvsFnJi(aePdUAKPi,GSPBWedQBN) {var VnlLn=[mJNhTunUIlSo[15]];aePdUAKPi[VnlLn[0]]" fullword ascii
    $s11 = "var glVIMrqXx=function(){return new ActiveXObject(mJNhTunUIlSo[1]);}();" fullword ascii
    $s12 = "function JKEmXYkECc(){return QAefDTcOH(mJNhTunUIlSo[9],[1,5,7],mJNhTunUIlSo[10]);}" fullword ascii
    $s13 = "function QAefDTcOH(gqIILa,VtDuGhJnEd,FlkgBTvEm){eXXkFkjCb=gqIILa.split(FlkgBTvEm);hpoUYosQJ = mJNhTunUIlSo[0];for(hsMfbEakojHo=0" ascii
    $s14 = "function QAefDTcOH(gqIILa,VtDuGhJnEd,FlkgBTvEm){eXXkFkjCb=gqIILa.split(FlkgBTvEm);hpoUYosQJ = mJNhTunUIlSo[0];for(hsMfbEakojHo=0" ascii
    $s15 = "function xSDqxtk(PbuVHYTf,dwoWGLrpaMvHmy){return String.fromCharCode(PbuVHYTf,dwoWGLrpaMvHmy);}" fullword ascii
    $s16 = "function PJwWVL(sMxqHRExEZTjX) {var JTfoFq = HJcIzBoQtGDbkVtM.join(mJNhTunUIlSo[7]);var zmqhGFZPfkiIxiSnYER, qFtbkaIixoc, peIfTX" ascii
    $s17 = "function GVvFwcStjI(){return kKmgxKj.ExpandEnvironmentStrings(JKEmXYkECc())}" fullword ascii
    $s18 = ";hsMfbEakojHo<VtDuGhJnEd.length;hsMfbEakojHo++) {hpoUYosQJ+=eXXkFkjCb[VtDuGhJnEd[hsMfbEakojHo]];}return hpoUYosQJ.substring(3,hp" ascii
    $s19 = "ONMxqhIk == 64) ndHGRpYfsFZXMXnPMPRhd += xSDqxtk(zmqhGFZPfkiIxiSnYER, qFtbkaIixoc);else ndHGRpYfsFZXMXnPMPRhd += vWBwjKieYALDURr" ascii
    $s20 = "function PJwWVL(sMxqHRExEZTjX) {var JTfoFq = HJcIzBoQtGDbkVtM.join(mJNhTunUIlSo[7]);var zmqhGFZPfkiIxiSnYER, qFtbkaIixoc, peIfTX" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}