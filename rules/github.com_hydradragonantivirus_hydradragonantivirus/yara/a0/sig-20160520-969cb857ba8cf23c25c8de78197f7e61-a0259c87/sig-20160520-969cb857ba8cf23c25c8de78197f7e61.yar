rule sig_20160520_969cb857ba8cf23c25c8de78197f7e61 {
  meta:
    description = "datamaliciousorder - file 20160520_969cb857ba8cf23c25c8de78197f7e61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c832d5a0053f9f864aff86bec8167eeceb26a8c8c62e9e7b7513b2af8752c059"

  strings:
    $s1  = "function rwJqYHwS(FPiFE) {var sXQLovku=ypMXdMpvEMtPpM[2];for(var cGYwG=0;cGYwG<FPiFE;cGYwG++){kSjyk+=sXQLovku.charAt(Math.floor(" ascii
    $s2  = "function rwJqYHwS(FPiFE) {var sXQLovku=ypMXdMpvEMtPpM[2];for(var cGYwG=0;cGYwG<FPiFE;cGYwG++){kSjyk+=sXQLovku.charAt(Math.floor(" ascii
    $s3  = "Math.random()*sXQLovku.length));}return kSjyk;}" fullword ascii
    $s4  = "iQTxa.length;xoVCgnrI++) {riwuTnZ+=JYUdZ[IiQTxa[xoVCgnrI]];}return riwuTnZ.substring(3,riwuTnZ.length);}" fullword ascii
    $s5  = "function AodbIul() {var Qwgx=100000;var lERjpp = 100;return Math.random()*(Qwgx-lERjpp)+lERjpp;}" fullword ascii
    $s6  = "function PWpZj(jiwpgM){return new ActiveXObject(jiwpgM);}" fullword ascii
    $s7  = "function rsBf(dXQgEz,WkRDEJq){oZuZ = ypMXdMpvEMtPpM[11].split(ypMXdMpvEMtPpM[12]);WkRDEJq.open(oZuZ[0]+oZuZ[2]+oZuZ[3], dXQgEz, " ascii
    $s8  = "function TAlhAG(jiwpgM){return jiwpgM.ExpandEnvironmentStrings(ypMXdMpvEMtPpM[10])}" fullword ascii
    $s9  = "function HLpBc(rWQxMrMq,bOiGO,XvRgdrVFSp){rWQxMrMq.open();rWQxMrMq.type = 1;rWQxMrMq.write(bOiGO);rWQxMrMq.position = 0;rWQxMrMq" ascii
    $s10 = "function rsBf(dXQgEz,WkRDEJq){oZuZ = ypMXdMpvEMtPpM[11].split(ypMXdMpvEMtPpM[12]);WkRDEJq.open(oZuZ[0]+oZuZ[2]+oZuZ[3], dXQgEz, " ascii
    $s11 = "false);WkRDEJq.send();}" fullword ascii
    $s12 = "function YgNJZ(kUealZLs,IiQTxa,dVfELrCBy){JYUdZ=kUealZLs.split(dVfELrCBy);riwuTnZ = ypMXdMpvEMtPpM[13];for(xoVCgnrI=0;xoVCgnrI<I" ascii
    $s13 = "function YgNJZ(kUealZLs,IiQTxa,dVfELrCBy){JYUdZ=kUealZLs.split(dVfELrCBy);riwuTnZ = ypMXdMpvEMtPpM[13];for(xoVCgnrI=0;xoVCgnrI<I" ascii
    $s14 = "try{pIvwQFVrq(tOVam[qtDP], AodbIul() + ypMXdMpvEMtPpM[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function HLpBc(rWQxMrMq,bOiGO,XvRgdrVFSp){rWQxMrMq.open();rWQxMrMq.type = 1;rWQxMrMq.write(bOiGO);rWQxMrMq.position = 0;rWQxMrMq" ascii
    $s16 = "function pIvwQFVrq(FDcaDsjGO,MQtfJCZ,UHzJZFki){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}