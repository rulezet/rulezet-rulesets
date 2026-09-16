rule sig_20160523_4a9e32a766f05aab9eb7cecdf7db9b50 {
  meta:
    description = "datamaliciousorder - file 20160523_4a9e32a766f05aab9eb7cecdf7db9b50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3ef3a2d242974f6e98f3de81d6847fb5dbed718547c0dcee6a39cce52b72da4"

  strings:
    $s1  = "function HvtIaGIKfT(ydoXyfJW,yPVnRBSyVThU) {ydoXyfJW.Run(yPVnRBSyVThU, 0x1, 0x0);}" fullword ascii
    $s2  = "function vSmBPASYKd() {return/*yQAoMNRYIdtJfoQmGISyrXEvCwkzZvGivzaouwdGZkkdeWJOwqHMImmiGkBcsqKyVlhOokRuOkDnkEJJRcKPXyxeHygsFZfHd" ascii
    $s3  = "function PKoEYULJ(WLyzw) {var rzirSMrB=bpRZWkHzV[13];for(var sujpo=0;sujpo<WLyzw;sujpo++){udgUJ+=rzirSMrB.charAt(Math.floor(Math" ascii
    $s4  = "function PKoEYULJ(WLyzw) {var rzirSMrB=bpRZWkHzV[13];for(var sujpo=0;sujpo<WLyzw;sujpo++){udgUJ+=rzirSMrB.charAt(Math.floor(Math" ascii
    $s5  = "function GwRUnPX() {var VWZE=100000;var JEbLFC = 100;return iToMOQC()*(VWZE-JEbLFC)+JEbLFC;}" fullword ascii
    $s6  = "function arGdb(uYHBluNC,ysAWM,pwQKoyezpe){yTZE(uYHBluNC);kKDmSkeG(uYHBluNC);pNxOqxn(uYHBluNC,ysAWM);siRkqyFaU(uYHBluNC);vpff(uYH" ascii
    $s7  = "function arGdb(uYHBluNC,ysAWM,pwQKoyezpe){yTZE(uYHBluNC);kKDmSkeG(uYHBluNC);pNxOqxn(uYHBluNC,ysAWM);siRkqyFaU(uYHBluNC);vpff(uYH" ascii
    $s8  = "function yTZE(NvjyHf) {NvjyHf.open();}" fullword ascii
    $s9  = "function JsxWm(wRaCZGXr,jwEseY,OJCRQFSiP){IGSmk=wRaCZGXr.split(OJCRQFSiP);wjMdLnr = bpRZWkHzV[12];for(ThazQWzf=0;ThazQWzf<jwEseY" ascii
    $s10 = "function MbYC(DTEWag,gMEISUY){QyOQ = bpRZWkHzV[10].split(bpRZWkHzV[11]);gMEISUY.open(QyOQ[0]+QyOQ[2]+QyOQ[3], DTEWag, false);gME" ascii
    $s11 = "if(hfMJ>gIhIl.length) break;" fullword ascii
    $s12 = ".random()*rzirSMrB.length));}return udgUJ;}" fullword ascii
    $s13 = "function iToMOQC(){return Math.random();}" fullword ascii
    $s14 = "function JsxWm(wRaCZGXr,jwEseY,OJCRQFSiP){IGSmk=wRaCZGXr.split(OJCRQFSiP);wjMdLnr = bpRZWkHzV[12];for(ThazQWzf=0;ThazQWzf<jwEseY" ascii
    $s15 = "function UslFPD(eTiXuM){return eTiXuM.ExpandEnvironmentStrings(bpRZWkHzV[9])}" fullword ascii
    $s16 = "function siRkqyFaU(RjaXlG) {var dElcdLHETz=[];RjaXlG.position=dElcdLHETz.length*(5562029-118);}" fullword ascii
    $s17 = "function kKDmSkeG(RTSMZhHLN) {RTSMZhHLN.type=1;}" fullword ascii
    $s18 = "function MbYC(DTEWag,gMEISUY){QyOQ = bpRZWkHzV[10].split(bpRZWkHzV[11]);gMEISUY.open(QyOQ[0]+QyOQ[2]+QyOQ[3], DTEWag, false);gME" ascii
    $s19 = "function pNxOqxn(jLOE,AgHXc) {jLOE.write(AgHXc);}" fullword ascii
    $s20 = "function Heetg(eTiXuM){return new ActiveXObject(eTiXuM);}" fullword ascii

  condition:
    uint16(0) == 0x0f27 and
    8 of them
}