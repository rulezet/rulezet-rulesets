rule sig_20160524_4e6d07a2c1becb37c8fc39e425048b7f {
  meta:
    description = "datamaliciousorder - file 20160524_4e6d07a2c1becb37c8fc39e425048b7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9221640e8d890ff2784d50ce6f287f80ac7366c82e6c21fd6a39358d34314f7"

  strings:
    $s1  = "function SlFrBvlPGm(NKAhqmZg,xgwFoFJFvteD) {NKAhqmZg.Run(xgwFoFJFvteD, 0x1, 0x0);}" fullword ascii
    $s2  = "function SsYbLwke(zdtQg) {var TmEgWYlv=ueHTFcbxDviXyCmJx[13];for(var RqczK=0;RqczK<zdtQg;RqczK++){zXqek+=TmEgWYlv.charAt(Math.fl" ascii
    $s3  = "function SsYbLwke(zdtQg) {var TmEgWYlv=ueHTFcbxDviXyCmJx[13];for(var RqczK=0;RqczK<zdtQg;RqczK++){zXqek+=TmEgWYlv.charAt(Math.fl" ascii
    $s4  = "function eUZM(OxtciL,MxKQqOs){qPsF = ueHTFcbxDviXyCmJx[10].split(ueHTFcbxDviXyCmJx[11]);MxKQqOs.open(qPsF[0]+qPsF[2]+qPsF[3], Ox" ascii
    $s5  = "function zejgAi(djRYes){return djRYes.ExpandEnvironmentStrings(ueHTFcbxDviXyCmJx[9])}" fullword ascii
    $s6  = "function eUZM(OxtciL,MxKQqOs){qPsF = ueHTFcbxDviXyCmJx[10].split(ueHTFcbxDviXyCmJx[11]);MxKQqOs.open(qPsF[0]+qPsF[2]+qPsF[3], Ox" ascii
    $s7  = "function JBoN(yfPGrg) {yfPGrg.open();}" fullword ascii
    $s8  = "function ykNLVrl(nNJpC) {nNJpC.close();}" fullword ascii
    $s9  = "function ASSqMWhU(rRNEHZRFA) {rRNEHZRFA.type=1;}" fullword ascii
    $s10 = "function xgmGgQPAt(GlTIFL) {var BWubQJcrGS=[];GlTIFL.position=BWubQJcrGS.length*(6177163-398);}" fullword ascii
    $s11 = "function vWInCjZ(Nthp,rsWPR) {Nthp.write(rsWPR);}" fullword ascii
    $s12 = "tciL, false);MxKQqOs.send();}" fullword ascii
    $s13 = "function SPotY(qyffjULg,sjWrpv,ZEZiDnVDW){ChYom=qyffjULg.split(ZEZiDnVDW);GRTChoQ = ueHTFcbxDviXyCmJx[12];for(iajOHOgq=0;iajOHOg" ascii
    $s14 = "function jtmX(UtCUNbT,kTEdQSM) {UtCUNbT.saveToFile(kTEdQSM, 2);}" fullword ascii
    $s15 = "function NgaQz(djRYes){return new ActiveXObject(djRYes);}" fullword ascii
    $s16 = "function RCtJizf() {var pXxc=100000;var ZcvNyP = 100;return sSOTjdp()*(pXxc-ZcvNyP)+ZcvNyP;}" fullword ascii
    $s17 = "function SPotY(qyffjULg,sjWrpv,ZEZiDnVDW){ChYom=qyffjULg.split(ZEZiDnVDW);GRTChoQ = ueHTFcbxDviXyCmJx[12];for(iajOHOgq=0;iajOHOg" ascii
    $s18 = "function axudc(DbvyMgWn,DtZVi,buseOAfySj){JBoN(DbvyMgWn);ASSqMWhU(DbvyMgWn);vWInCjZ(DbvyMgWn,DtZVi);xgmGgQPAt(DbvyMgWn);jtmX(Dbv" ascii
    $s19 = "q<sjWrpv.length;iajOHOgq++) {GRTChoQ+=ChYom[sjWrpv[iajOHOgq]];}return GRTChoQ.substring(3,GRTChoQ.length);}" fullword ascii
    $s20 = "function axudc(DbvyMgWn,DtZVi,buseOAfySj){JBoN(DbvyMgWn);ASSqMWhU(DbvyMgWn);vWInCjZ(DbvyMgWn,DtZVi);xgmGgQPAt(DbvyMgWn);jtmX(Dbv" ascii

  condition:
    uint16(0) == 0x1627 and
    8 of them
}