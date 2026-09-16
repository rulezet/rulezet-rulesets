rule sig_20160520_92fc8b5240171a9d1f19d7ec4af9eea8 {
  meta:
    description = "datamaliciousorder - file 20160520_92fc8b5240171a9d1f19d7ec4af9eea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "515ea18831d6129db8b634370f3dc0fa861ef3d0539ffbbf1d74d3ccc0de7be3"

  strings:
    $s1  = "function qksLPTNC(GAKeb) {var XhUMBBeX=ciXFKr[2];for(var fTmua=0;fTmua<GAKeb;fTmua++){FzpfL+=XhUMBBeX.charAt(Math.floor(Math.ran" ascii
    $s2  = "function qksLPTNC(GAKeb) {var XhUMBBeX=ciXFKr[2];for(var fTmua=0;fTmua<GAKeb;fTmua++){FzpfL+=XhUMBBeX.charAt(Math.floor(Math.ran" ascii
    $s3  = "function bRJxbuszz(EvEzVFCrd,ZwqHpET,LMSaUbEi){" fullword ascii
    $s4  = "function CKsD(bFYNts,UPsqENh){rcoz = ciXFKr[11].split(ciXFKr[12]);UPsqENh.open(rcoz[0]+rcoz[2]+rcoz[3], bFYNts, false);UPsqENh.s" ascii
    $s5  = "function LRukf(pYdrlCfI,whXNp,kJUIKTMReH){pYdrlCfI.open();pYdrlCfI.type = 1;pYdrlCfI.write(whXNp);pYdrlCfI.position = 0;pYdrlCfI" ascii
    $s6  = "try{oEOYlLP=bRJxbuszz(PcIJs[aKGV], kgLiYsZ() + ciXFKr[9], 1)}catch(e){}; " fullword ascii
    $s7  = "dom()*XhUMBBeX.length));}return FzpfL;}" fullword ascii
    $s8  = "function UmOAP(BFQYfCeC,kApeAO,VKpmVYmlM){kOmyc=BFQYfCeC.split(VKpmVYmlM);EMscIZV = ciXFKr[13];for(ZDDttaGp=0;ZDDttaGp<kApeAO.le" ascii
    $s9  = "function UmOAP(BFQYfCeC,kApeAO,VKpmVYmlM){kOmyc=BFQYfCeC.split(VKpmVYmlM);EMscIZV = ciXFKr[13];for(ZDDttaGp=0;ZDDttaGp<kApeAO.le" ascii
    $s10 = "function KkzuR(bVgaVm){return new ActiveXObject(bVgaVm);}" fullword ascii
    $s11 = "function LRukf(pYdrlCfI,whXNp,kJUIKTMReH){pYdrlCfI.open();pYdrlCfI.type = 1;pYdrlCfI.write(whXNp);pYdrlCfI.position = 0;pYdrlCfI" ascii
    $s12 = "function CKsD(bFYNts,UPsqENh){rcoz = ciXFKr[11].split(ciXFKr[12]);UPsqENh.open(rcoz[0]+rcoz[2]+rcoz[3], bFYNts, false);UPsqENh.s" ascii
    $s13 = "function DqcpKr(bVgaVm){return bVgaVm.ExpandEnvironmentStrings(ciXFKr[10])}" fullword ascii
    $s14 = "function kgLiYsZ() {var gXdS=100000;var Nozhaz = 100;return Math.random()*(gXdS-Nozhaz)+Nozhaz;}" fullword ascii
    $s15 = "ngth;ZDDttaGp++) {EMscIZV+=kOmyc[kApeAO[ZDDttaGp]];}return EMscIZV.substring(3,EMscIZV.length);}" fullword ascii
    $s16 = "if (oEOYlLP==0) break;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}