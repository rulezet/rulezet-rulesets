rule sig_20151217_a3c07af71b9864210a9b7c49a476074b {
  meta:
    description = "datamaliciousorder - file 20151217_a3c07af71b9864210a9b7c49a476074b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65509e2e4ffa2b55cff537dfd6fde0214f27bcd9d61732da3790180007b2a43f"

  strings:
    $s1  = "function CngXNIurEDtEagPzF(uybcN){FQRkKBnJbWV= '';EVaHAESzZUG=Math.round((Math.pow(Math.sin(966), 2) + Math.pow(Math.cos(966), 2" ascii
    $s2  = "w(Math.cos(275), 2) - 1)));} fXzZSysrZ[EVaHAESzZUG]++;}EVaHAESzZUG++;} return FQRkKBnJbWV}" fullword ascii
    $s3  = ") - 1));while(true){if (EVaHAESzZUG >= (1751+709)/410){break;}fXzZSysrZ[EVaHAESzZUG]=Math.round((Math.pow(Math.sin(441), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(441), 2) - 1)); while(true) { if(fXzZSysrZ[EVaHAESzZUG] > uybcN[EVaHAESzZUG].length-(362+567)/929) { break; } if" ascii
    $s5  = "function CngXNIurEDtEagPzF(uybcN){FQRkKBnJbWV= '';EVaHAESzZUG=Math.round((Math.pow(Math.sin(966), 2) + Math.pow(Math.cos(966), 2" ascii
    $s6  = "function zfeOuSx(sldfqxsenhIPuJhdwvUgtbjKjinYdujLTyyW) {return !wngmqpLtByB(uDrreCTXzAOdOIe(sldfqxsenhIPuJhdwvUgtbjKjinYdujLTyyW" ascii
    $s7  = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s8  = "function uDrreCTXzAOdOIe(nRmwdLnVhhtLqmLBlzA) {return parseFloat(nRmwdLnVhhtLqmLBlzA);}" fullword ascii
    $s9  = "function vnQaoezIdUqdQKv(mFuSRyWDoRSMpjDbs,JeogglVNwojdROtMIWoiNGCZnHWuKgAjfC,jaoKQOUrBEcFGyYXriogwilxDGkfnJxPYnf){eval(mFuSRyWD" ascii
    $s10 = "function KCsrichDnBJzodIpLmgHXlEqoTfoMlXPlbNFPwgDlGtyzXEPcjETAp(eUVfJqLCFpspk,ITsPBlvNdWoAAp){ return AElAAEZ[zUwxYqgT[KgNcp(eUV" ascii
    $s11 = "function D(YFxrUAxPtljR,SLfJkswPbKVhqx){YFxrUAxPtljR.push(SLfJkswPbKVhqx);}" fullword ascii
    $s12 = "z);return FUqRA;}" fullword ascii
    $s13 = "function KgNcp(oXtuELYwPFR,VPBWLgRRAdACc,OjabBRJz){gIGC=ZRbAbPkYHwwwoKNXN(oXtuELYwPFR,VPBWLgRRAdACc);FUqRA=gIGC.toString(OjabBRJ" ascii
    $s14 = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s15 = "function ZRbAbPkYHwwwoKNXN(PJQfmwOmAF,MhiZtNgJdC) {return parseInt(PJQfmwOmAF,MhiZtNgJdC);}" fullword ascii
    $s16 = "function zfeOuSx(sldfqxsenhIPuJhdwvUgtbjKjinYdujLTyyW) {return !wngmqpLtByB(uDrreCTXzAOdOIe(sldfqxsenhIPuJhdwvUgtbjKjinYdujLTyyW" ascii
    $s17 = "function e(tlfMVCMpyyedXt,fEYtvhdrmjtHW,VQLvbpcutLs) {tlfMVCMpyyedXt[fEYtvhdrmjtHW]=VQLvbpcutLs;}" fullword ascii
    $s18 = "function wngmqpLtByB(IWZKjQZUgyRGwq) {return isNaN(IWZKjQZUgyRGwq);}" fullword ascii
    $s19 = "function KgNcp(oXtuELYwPFR,VPBWLgRRAdACc,OjabBRJz){gIGC=ZRbAbPkYHwwwoKNXN(oXtuELYwPFR,VPBWLgRRAdACc);FUqRA=gIGC.toString(OjabBRJ" ascii
    $s20 = "function uHNnLOtAOdRZ(SqYZKVJUFqQwP) {return isFinite(SqYZKVJUFqQwP);}" fullword ascii

  condition:
    uint16(0) == 0x557a and
    8 of them
}