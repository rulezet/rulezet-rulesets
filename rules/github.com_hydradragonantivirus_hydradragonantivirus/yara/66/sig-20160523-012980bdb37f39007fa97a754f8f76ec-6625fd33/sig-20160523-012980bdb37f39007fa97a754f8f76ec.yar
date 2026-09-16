rule sig_20160523_012980bdb37f39007fa97a754f8f76ec {
  meta:
    description = "datamaliciousorder - file 20160523_012980bdb37f39007fa97a754f8f76ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf168751b525bce9e20dcf10e4203944c6b63b604dd9aa74a121f6825cf582c"

  strings:
    $s1  = "function jmifPPjqkb(HqBjkryQ,TLGrsocYmBly) {HqBjkryQ.Run(TLGrsocYmBly, 0x1, 0x0);}" fullword ascii
    $s2  = "function mTVtIoYG(IGZaE) {var PiJNLCTx=rpTgnanQtpZWLTz[13];for(var IBYOK=0;IBYOK<IGZaE;IBYOK++){nUzkP+=PiJNLCTx.charAt(Math.floo" ascii
    $s3  = "function mTVtIoYG(IGZaE) {var PiJNLCTx=rpTgnanQtpZWLTz[13];for(var IBYOK=0;IBYOK<IGZaE;IBYOK++){nUzkP+=PiJNLCTx.charAt(Math.floo" ascii
    $s4  = "JRDOHL.length;vOFGXGBK++) {xGnkuzM+=TTeZK[JRDOHL[vOFGXGBK]];}return xGnkuzM.substring(3,xGnkuzM.length);}" fullword ascii
    $s5  = "function phhzZzCAmt() {return/*fbUYBCFVALVPtPROsEhHuxrlvwLeSSyLHEakbAPnQeNWpItGlEEWzxeXzSrjjMskzUMbpDHeCLleNivGAKHEhNVxiGtwLOtFI" ascii
    $s6  = "function ZSFmn(hHflMX){return new ActiveXObject(hHflMX);}" fullword ascii
    $s7  = "function yJWDXYI(){return Math.random();}" fullword ascii
    $s8  = "function SyTUKBifN(WToOKI) {var lKMbVFcMrf=[];WToOKI.position=lKMbVFcMrf.length*(3564111-467);}" fullword ascii
    $s9  = "function JWWU(RVkGlw,DTvyFHt){FsYr = rpTgnanQtpZWLTz[10].split(rpTgnanQtpZWLTz[11]);DTvyFHt.open(FsYr[0]+FsYr[2]+FsYr[3], RVkGlw" ascii
    $s10 = "function clmBZ(LprlmTsR,gfRoQ,RwNNrRZWxP){dGyE(LprlmTsR);DgJfIWLK(LprlmTsR);rMotxoH(LprlmTsR,gfRoQ);SyTUKBifN(LprlmTsR);OeXx(Lpr" ascii
    $s11 = ", false);DTvyFHt.send();}" fullword ascii
    $s12 = "r(Math.random()*PiJNLCTx.length));}return nUzkP;}" fullword ascii
    $s13 = "function rMotxoH(HIUY,gRVkW) {HIUY.write(gRVkW);}" fullword ascii
    $s14 = "function OtlPwv(hHflMX){return hHflMX.ExpandEnvironmentStrings(rpTgnanQtpZWLTz[9])}" fullword ascii
    $s15 = "function dGyE(gJmZVZ) {gJmZVZ.open();}" fullword ascii
    $s16 = "if(UefM>eCFBM.length) break;" fullword ascii
    $s17 = "function clmBZ(LprlmTsR,gfRoQ,RwNNrRZWxP){dGyE(LprlmTsR);DgJfIWLK(LprlmTsR);rMotxoH(LprlmTsR,gfRoQ);SyTUKBifN(LprlmTsR);OeXx(Lpr" ascii
    $s18 = "function DgJfIWLK(UMijVyLyw) {UMijVyLyw.type=1;}" fullword ascii
    $s19 = "function JWWU(RVkGlw,DTvyFHt){FsYr = rpTgnanQtpZWLTz[10].split(rpTgnanQtpZWLTz[11]);DTvyFHt.open(FsYr[0]+FsYr[2]+FsYr[3], RVkGlw" ascii
    $s20 = "function BGwmNiw(OeRGv) {OeRGv.close();}" fullword ascii

  condition:
    uint16(0) == 0x0e27 and
    8 of them
}