rule sig_20160523_5e19a5aaee9b23ccafdd10b4dc8a63f6 {
  meta:
    description = "datamaliciousorder - file 20160523_5e19a5aaee9b23ccafdd10b4dc8a63f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d8f67884486cacfe7d8fe2ec4e8c6fcbd659e66fa1976ed89ae4112d2331b5"

  strings:
    $s1  = "function wvsvMkbByN() {return/*NcnhhYTbBbHwEeueGwIVlVoyOlSneWPEJIKDNpfFpiPvNyVZyOvQaGzEwwSFKBQtEHkxUpLVtZcKDvjmohszFOUGSzETdbNJe" ascii
    $s2  = "function cWuutETBMM(MunxtSLr,eSvcddVrdEvQ) {MunxtSLr.Run(eSvcddVrdEvQ, 0x1, 0x0);}" fullword ascii
    $s3  = "function pNImzVAF(JzMfa) {var aXwsmYcf=FPhJdLoUx[13];for(var fbKlP=0;fbKlP<JzMfa;fbKlP++){cOKsv+=aXwsmYcf.charAt(Math.floor(Math" ascii
    $s4  = "function pNImzVAF(JzMfa) {var aXwsmYcf=FPhJdLoUx[13];for(var fbKlP=0;fbKlP<JzMfa;fbKlP++){cOKsv+=aXwsmYcf.charAt(Math.floor(Math" ascii
    $s5  = "function wvsvMkbByN() {return/*NcnhhYTbBbHwEeueGwIVlVoyOlSneWPEJIKDNpfFpiPvNyVZyOvQaGzEwwSFKBQtEHkxUpLVtZcKDvjmohszFOUGSzETdbNJe" ascii
    $s6  = "function fkeMhi(iGjWgH){return iGjWgH.ExpandEnvironmentStrings(FPhJdLoUx[9])}" fullword ascii
    $s7  = "function NpVS(auMvVw,CLBQWQC){CuvO = FPhJdLoUx[10].split(FPhJdLoUx[11]);CLBQWQC.open(CuvO[0]+CuvO[2]+CuvO[3], auMvVw, false);CLB" ascii
    $s8  = "if(gbtz>STPUU.length) break;" fullword ascii
    $s9  = "function NpVS(auMvVw,CLBQWQC){CuvO = FPhJdLoUx[10].split(FPhJdLoUx[11]);CLBQWQC.open(CuvO[0]+CuvO[2]+CuvO[3], auMvVw, false);CLB" ascii
    $s10 = "function Ghnkf(aNJWXPvZ,IVnHLY,GnIRXYvmM){aexyd=aNJWXPvZ.split(GnIRXYvmM);MBHnUcF = FPhJdLoUx[12];for(ztUUFGGY=0;ztUUFGGY<IVnHLY" ascii
    $s11 = "function xjdTp(iGjWgH){return new ActiveXObject(iGjWgH);}" fullword ascii
    $s12 = "function xCJnIGZ(mNMG,OzzZR) {mNMG.write(OzzZR);}" fullword ascii
    $s13 = "function jENLcfywJpLRf() {wvsvMkbByN().Sleep(2484920-687);}" fullword ascii
    $s14 = "function fdWUl(mKYtqTQB,hwWKU,opYtxilVRW){euoZ(mKYtqTQB);xudJuFYf(mKYtqTQB);xCJnIGZ(mKYtqTQB,hwWKU);WRRFTtqtm(mKYtqTQB);DwZl(mKY" ascii
    $s15 = "function DwZl(rGffPgq,NmXelyA) {rGffPgq.saveToFile(NmXelyA, 2);}" fullword ascii
    $s16 = "function fdWUl(mKYtqTQB,hwWKU,opYtxilVRW){euoZ(mKYtqTQB);xudJuFYf(mKYtqTQB);xCJnIGZ(mKYtqTQB,hwWKU);WRRFTtqtm(mKYtqTQB);DwZl(mKY" ascii
    $s17 = "function Ghnkf(aNJWXPvZ,IVnHLY,GnIRXYvmM){aexyd=aNJWXPvZ.split(GnIRXYvmM);MBHnUcF = FPhJdLoUx[12];for(ztUUFGGY=0;ztUUFGGY<IVnHLY" ascii
    $s18 = "function JzvSQAS() {var RExi=100000;var vBvOJu = 100;return RnlRxVZ()*(RExi-vBvOJu)+vBvOJu;}" fullword ascii
    $s19 = "function WRRFTtqtm(TRwHYD) {var keezHMkIrg=[];TRwHYD.position=keezHMkIrg.length*(2104440-145);}" fullword ascii
    $s20 = ".length;ztUUFGGY++) {MBHnUcF+=aexyd[IVnHLY[ztUUFGGY]];}return MBHnUcF.substring(3,MBHnUcF.length);}" fullword ascii

  condition:
    uint16(0) == 0x0c27 and
    8 of them
}