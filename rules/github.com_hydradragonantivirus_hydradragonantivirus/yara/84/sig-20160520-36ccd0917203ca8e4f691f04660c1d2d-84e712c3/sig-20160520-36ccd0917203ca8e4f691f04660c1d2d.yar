rule sig_20160520_36ccd0917203ca8e4f691f04660c1d2d {
  meta:
    description = "datamaliciousorder - file 20160520_36ccd0917203ca8e4f691f04660c1d2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c81f5e5dba6f867e8a766a6a09be5e587e14e4cb2cc5a5b0082ebfdeeb9d3d2c"

  strings:
    $s1  = "function ajOHOgqC(hYomG) {var RTChoQPk=XONZzuiZUJKbtIOKL[2];for(var wsSOT=0;wsSOT<hYomG;wsSOT++){jdpJB+=RTChoQPk.charAt(Math.flo" ascii
    $s2  = "function ajOHOgqC(hYomG) {var RTChoQPk=XONZzuiZUJKbtIOKL[2];for(var wsSOT=0;wsSOT<hYomG;wsSOT++){jdpJB+=RTChoQPk.charAt(Math.flo" ascii
    $s3  = "function uOUjsR(YgNppw){return YgNppw.ExpandEnvironmentStrings(XONZzuiZUJKbtIOKL[10])}" fullword ascii
    $s4  = "function EDSlZ(bpVBVITI,pjYsO,BAdyYsOWkR){bpVBVITI.open();bpVBVITI.type = 1;bpVBVITI.write(pjYsO);bpVBVITI.position = 0;bpVBVITI" ascii
    $s5  = "function exhmA(YgNppw){return new ActiveXObject(YgNppw);}" fullword ascii
    $s6  = "function gsjWrpv() {var ZEZi=100000;var DnVDWi = 100;return Math.random()*(ZEZi-DnVDWi)+DnVDWi;}" fullword ascii
    $s7  = "if (WhUrRNE==0) break;" fullword ascii
    $s8  = "j<ahSAxX.length;DWCfIcxj++) {NfkVPCf+=nZfHm[ahSAxX[DWCfIcxj]];}return NfkVPCf.substring(3,NfkVPCf.length);}" fullword ascii
    $s9  = "function KrDhN(JPFweGwd,ahSAxX,CeShNIjql){nZfHm=JPFweGwd.split(CeShNIjql);NfkVPCf = XONZzuiZUJKbtIOKL[13];for(DWCfIcxj=0;DWCfIcx" ascii
    $s10 = "function EDSlZ(bpVBVITI,pjYsO,BAdyYsOWkR){bpVBVITI.open();bpVBVITI.type = 1;bpVBVITI.write(pjYsO);bpVBVITI.position = 0;bpVBVITI" ascii
    $s11 = "try{WhUrRNE=PGrgASSqM(ffjUL[jOWg], gsjWrpv() + XONZzuiZUJKbtIOKL[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function KrDhN(JPFweGwd,ahSAxX,CeShNIjql){nZfHm=JPFweGwd.split(CeShNIjql);NfkVPCf = XONZzuiZUJKbtIOKL[13];for(DWCfIcxj=0;DWCfIcx" ascii
    $s13 = "or(Math.random()*RTChoQPk.length));}return jdpJB;}" fullword ascii
    $s14 = "function XoxQ(EfwGfz,sgzcYHl){Sxao = XONZzuiZUJKbtIOKL[11].split(XONZzuiZUJKbtIOKL[12]);sgzcYHl.open(Sxao[0]+Sxao[2]+Sxao[3], Ef" ascii
    $s15 = "function XoxQ(EfwGfz,sgzcYHl){Sxao = XONZzuiZUJKbtIOKL[11].split(XONZzuiZUJKbtIOKL[12]);sgzcYHl.open(Sxao[0]+Sxao[2]+Sxao[3], Ef" ascii
    $s16 = "wGfz, false);sgzcYHl.send();}" fullword ascii
    $s17 = "function PGrgASSqM(HZRFAvWIn,CjZNthp,rsWPRxgm){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}