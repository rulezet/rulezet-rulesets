rule sig_20160523_1d41d0cf9e03063cc8d38fd089919abb {
  meta:
    description = "datamaliciousorder - file 20160523_1d41d0cf9e03063cc8d38fd089919abb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7e569f001fbc9b2787271c345c2b389edb6eb8eafee0066f7ea106c493119a4"

  strings:
    $s1  = "function CwddFXRGbF() {return/*GHFqfBIfQgLBndMJMepkKyfxbQnoqOKtvmkUhGnoGCBKlMWDnvWUIUuDSPIRIEJvbAnqQruKRlltwEbCklNUbonBsOTKZWDdI" ascii
    $s2  = "function iNVZFKOvye(nahDKMDj,RuIVivXgaiOU) {nahDKMDj.Run(RuIVivXgaiOU, 0x1, 0x0);}" fullword ascii
    $s3  = "function jihhyPOA(NMnkC) {var hBsUbJai=CMouNVeDCvcjDjLEJL[13];for(var ZhCBX=0;ZhCBX<NMnkC;ZhCBX++){onZuf+=hBsUbJai.charAt(Math.f" ascii
    $s4  = "function jihhyPOA(NMnkC) {var hBsUbJai=CMouNVeDCvcjDjLEJL[13];for(var ZhCBX=0;ZhCBX<NMnkC;ZhCBX++){onZuf+=hBsUbJai.charAt(Math.f" ascii
    $s5  = "function IRFP(bmwprb,SqyUOKO){RgxG = CMouNVeDCvcjDjLEJL[10].split(CMouNVeDCvcjDjLEJL[11]);SqyUOKO.open(RgxG[0]+RgxG[2]+RgxG[3], " ascii
    $s6  = "function dNBgN(TqBZJL){return new ActiveXObject(TqBZJL);}" fullword ascii
    $s7  = "qL<cKVlPZ.length;VlLyYUqL++) {LeDWyYt+=osEhm[cKVlPZ[VlLyYUqL]];}return LeDWyYt.substring(3,LeDWyYt.length);}" fullword ascii
    $s8  = "function REfyLYC(vLGt,kFcqu) {vLGt.write(kFcqu);}" fullword ascii
    $s9  = "function TQSDvVLIj(EhOyTS) {var QtqrkGsHBZ=[];EhOyTS.position=QtqrkGsHBZ.length*(9106682-578);}" fullword ascii
    $s10 = "function VRnzDFf(){return Math.random();}" fullword ascii
    $s11 = "bmwprb, false);SqyUOKO.send();}" fullword ascii
    $s12 = "function EeNJl(DMTdsEgJ,qDCBi,bkuZlamyKx){UTeS(DMTdsEgJ);mvGIwrgv(DMTdsEgJ);REfyLYC(DMTdsEgJ,qDCBi);TQSDvVLIj(DMTdsEgJ);IHDU(DMT" ascii
    $s13 = "function LlNgv(CRzchNYo,cKVlPZ,SeZEVVKkf){osEhm=CRzchNYo.split(SeZEVVKkf);LeDWyYt = CMouNVeDCvcjDjLEJL[12];for(VlLyYUqL=0;VlLyYU" ascii
    $s14 = "function CwddFXRGbF() {return/*GHFqfBIfQgLBndMJMepkKyfxbQnoqOKtvmkUhGnoGCBKlMWDnvWUIUuDSPIRIEJvbAnqQruKRlltwEbCklNUbonBsOTKZWDdI" ascii
    $s15 = "function RYhmKaPpEXYJk() {CwddFXRGbF().Sleep(2422868-447);}" fullword ascii
    $s16 = "function mnrXGlk() {var rmSb=100000;var RFEwan = 100;return VRnzDFf()*(rmSb-RFEwan)+RFEwan;}" fullword ascii
    $s17 = "loor(Math.random()*hBsUbJai.length));}return onZuf;}" fullword ascii
    $s18 = "function eZOSjrx(qctLq) {qctLq.close();}" fullword ascii
    $s19 = "function LlNgv(CRzchNYo,cKVlPZ,SeZEVVKkf){osEhm=CRzchNYo.split(SeZEVVKkf);LeDWyYt = CMouNVeDCvcjDjLEJL[12];for(VlLyYUqL=0;VlLyYU" ascii
    $s20 = "function IRFP(bmwprb,SqyUOKO){RgxG = CMouNVeDCvcjDjLEJL[10].split(CMouNVeDCvcjDjLEJL[11]);SqyUOKO.open(RgxG[0]+RgxG[2]+RgxG[3], " ascii

  condition:
    uint16(0) == 0x0227 and
    8 of them
}