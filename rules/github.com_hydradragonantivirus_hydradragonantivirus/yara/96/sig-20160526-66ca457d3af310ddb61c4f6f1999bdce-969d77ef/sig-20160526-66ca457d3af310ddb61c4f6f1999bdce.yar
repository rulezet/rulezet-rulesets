rule sig_20160526_66ca457d3af310ddb61c4f6f1999bdce {
  meta:
    description = "datamaliciousorder - file 20160526_66ca457d3af310ddb61c4f6f1999bdce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812208e5830a732931a28b95199c35ea171002836f44abf2cbd1082617748f7c"

  strings:
    $s1  = "function AFEzDjRwghSh(xVNkodfRKngSw) {var zlXWHBCyoMSqEZVvrlgB = DJeFUiTAhfgFxPI.join(neIzo[0]);var EnlvsLPuZrPUAuDwtaqWq, DKFHe" ascii
    $s2  = "6 + Math.round((Math.pow(Math.sin(49), 2) + Math.pow(Math.cos(49), 2) - 1))-722)) adQYwQo += nW(EnlvsLPuZrPUAuDwtaqWq);else if (" ascii
    $s3  = "function rDmymDlQtyTfZ(fcmTxNjFWzv,VhlUuFzvVUG){return fcmTxNjFWzv.charAt(VhlUuFzvVUG);}" fullword ascii
    $s4  = "function nW(VTMpINSPBtCXZsO){return String.fromCharCode(VTMpINSPBtCXZsO);}" fullword ascii
    $s5  = "function rFuPkJQSDDbdMqSJ(VmblBFVuuxrcKwncTu,zzYoWMcK){return String.fromCharCode(VmblBFVuuxrcKwncTu,zzYoWMcK);}" fullword ascii
    $s6  = "MqSJ(EnlvsLPuZrPUAuDwtaqWq, DKFHeJnEmKWwz);else adQYwQo += aCkfnj(EnlvsLPuZrPUAuDwtaqWq, DKFHeJnEmKWwz, xKJbfLfwiOIxYxLGvfsLPv);" ascii
    $s7  = "function uYEMWoFQe(tWTVjLTvUNprdhqda,pkhNdadstmfFRNFglgYlFQmi){return tWTVjLTvUNprdhqda.indexOf(pkhNdadstmfFRNFglgYlFQmi);}" fullword ascii
    $s8  = "} while (RsJpaNaoxXtoQDywW < xVNkodfRKngSw.length);return adQYwQo;}" fullword ascii
    $s9  = "function AFEzDjRwghSh(xVNkodfRKngSw) {var zlXWHBCyoMSqEZVvrlgB = DJeFUiTAhfgFxPI.join(neIzo[0]);var EnlvsLPuZrPUAuDwtaqWq, DKFHe" ascii
    $s10 = "function aCkfnj(MfPCAlOvmbb,XbVmuLiQKTHsDGCiDJyPs,GqsckJmwsW){return String.fromCharCode(MfPCAlOvmbb,XbVmuLiQKTHsDGCiDJyPs,Gqsck" ascii
    $s11 = "function aCkfnj(MfPCAlOvmbb,XbVmuLiQKTHsDGCiDJyPs,GqsckJmwsW){return String.fromCharCode(MfPCAlOvmbb,XbVmuLiQKTHsDGCiDJyPs,Gqsck" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}