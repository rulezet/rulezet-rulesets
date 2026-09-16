rule sig_20160527_961e501f9e2f762f94f591675aba4745 {
  meta:
    description = "datamaliciousorder - file 20160527_961e501f9e2f762f94f591675aba4745.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7488dbd4d75af75f8eb9c4c09420f65ad3ca44c032a6234d5c8b36c37510c97c"

  strings:
    $s1  = "function CHjawLRs(BFVbW,DdzNTkuWcqMoZyrgtYK){return BFVbW.charAt(DdzNTkuWcqMoZyrgtYK);}" fullword ascii
    $s2  = "function acAAt() {return WScript;}function JqastFn(){return JTFUGl.ExpandEnvironmentStrings(NVxneyBNSjf())}" fullword ascii
    $s3  = "function TDGQSLgKyDhVQ(){return BkNEhswSxxwO(PjMBPDrMAR[10],[2,4,8,10],PjMBPDrMAR[11]);}" fullword ascii
    $s4  = "function sjUnmVkMoN(TURvaQasoC,hvtcka){return String.fromCharCode(TURvaQasoC,hvtcka);}" fullword ascii
    $s5  = "function ZrGaw(JqxdGjywmMkxb) {var aTqsSFhZn = kVGohsWHVtDUKBarSNPMUa.join(PjMBPDrMAR[6]);var vnRpZByGANuk, mcsMRAhGoyssP, MSYle" ascii
    $s6  = "csMRAhGoyssP, MSYleqztPLKpfbJaNNieND);} while (GfRuTVWAot < JqxdGjywmMkxb.length);return mFEWHzQBi;}" fullword ascii
    $s7  = "function IQSUtqitnPc(rABIVb,yLPANvLdVkixkVRjB){return rABIVb.indexOf(yLPANvLdVkixkVRjB);}" fullword ascii
    $s8  = "PDrMAR[4],true);" fullword ascii
    $s9  = "MSYleqztPLKpfbJaNNieND = goBvAgROYgDE & 0xff;if (HISNDJoIyryJffnSJGvH == 64) mFEWHzQBi += Mc(vnRpZByGANuk);else if (sQjPBvqxpplJ" ascii
    $s10 = "var sHzIXAK = XpaTaVjnd.createtextfile(JTFUGl.ExpandEnvironmentStrings(PjMBPDrMAR[2]+PjMBPDrMAR[3])+String.fromCharCode(92)+PjMB" ascii
    $s11 = "function prWSlOWNc(zDSCJ,OYVFdl) {var CNmNQDs=[PjMBPDrMAR[15]];zDSCJ[CNmNQDs[0]](OYVFdl,0x1,0x0)}" fullword ascii
    $s12 = "MBPDrMAR[14];for(OLvpBNX=0;OLvpBNX<QcygaTuqLHC.length;OLvpBNX++) {TpyacWoqrKCC+=xUAdQXwsFEzcoH[QcygaTuqLHC[OLvpBNX]];}return Tpy" ascii
    $s13 = "function NVxneyBNSjf(){return BkNEhswSxxwO(PjMBPDrMAR[8],[1,5,7],PjMBPDrMAR[9]);}" fullword ascii
    $s14 = "function Mc(qRjuMWDGXFERtvUxjJZhtVi){return String.fromCharCode(qRjuMWDGXFERtvUxjJZhtVi);}" fullword ascii
    $s15 = "function mLlvDGrM(){return BkNEhswSxxwO(PjMBPDrMAR[12],[0,3,6],PjMBPDrMAR[13]);}" fullword ascii
    $s16 = "tgpOkXMLqudw = IQSUtqitnPc(aTqsSFhZn,CHjawLRs(JqxdGjywmMkxb,GfRuTVWAot++));goBvAgROYgDE = gthDRwJnccf<< 18 | WDDcZPh<< 12 | HISN" ascii
    $s17 = "var XpaTaVjnd=function(){return new ActiveXObject(PjMBPDrMAR[0]);}();" fullword ascii
    $s18 = "function BkNEhswSxxwO(BshFWQuzoAZ,QcygaTuqLHC,fFCFqLItGyYiLk){xUAdQXwsFEzcoH=BshFWQuzoAZ.split(fFCFqLItGyYiLk);TpyacWoqrKCC = Pj" ascii
    $s19 = "tgpOkXMLqudw == 64) mFEWHzQBi += sjUnmVkMoN(vnRpZByGANuk, mcsMRAhGoyssP);else mFEWHzQBi += pbNgKDLTBREWXPHwaPXYN(vnRpZByGANuk, m" ascii
    $s20 = "function BkNEhswSxxwO(BshFWQuzoAZ,QcygaTuqLHC,fFCFqLItGyYiLk){xUAdQXwsFEzcoH=BshFWQuzoAZ.split(fFCFqLItGyYiLk);TpyacWoqrKCC = Pj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}