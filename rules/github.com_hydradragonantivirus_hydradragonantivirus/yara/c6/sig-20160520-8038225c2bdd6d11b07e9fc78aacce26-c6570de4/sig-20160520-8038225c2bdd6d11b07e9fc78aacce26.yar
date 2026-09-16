rule sig_20160520_8038225c2bdd6d11b07e9fc78aacce26 {
  meta:
    description = "datamaliciousorder - file 20160520_8038225c2bdd6d11b07e9fc78aacce26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81038c9dd88a9dab5a58f6105bc622c7158bdd52c62ce5700efce80797aaf81c"

  strings:
    $s1  = "function UczPxcUp(VGnym) {var tpJVtmMU=kMTmcytUQVcvuZSmmvk[2];for(var lNbIa=0;lNbIa<VGnym;lNbIa++){gsirb+=tpJVtmMU.charAt(Math.f" ascii
    $s2  = "function UczPxcUp(VGnym) {var tpJVtmMU=kMTmcytUQVcvuZSmmvk[2];for(var lNbIa=0;lNbIa<VGnym;lNbIa++){gsirb+=tpJVtmMU.charAt(Math.f" ascii
    $s3  = "function bQySEtYKD(IkQiZdBag,xBhuOVP,HcnJmMJa){" fullword ascii
    $s4  = "function WhPE(qGtruS,WiFTKVX){qtXU = kMTmcytUQVcvuZSmmvk[11].split(kMTmcytUQVcvuZSmmvk[12]);WiFTKVX.open(qtXU[0]+qtXU[2]+qtXU[3]" ascii
    $s5  = "function dhVSO(jMGUpaEt,dxdKE,pVRylynOzE){jMGUpaEt.open();jMGUpaEt.type = 1;jMGUpaEt.write(dxdKE);jMGUpaEt.position = 0;jMGUpaEt" ascii
    $s6  = "function WhPE(qGtruS,WiFTKVX){qtXU = kMTmcytUQVcvuZSmmvk[11].split(kMTmcytUQVcvuZSmmvk[12]);WiFTKVX.open(qtXU[0]+qtXU[2]+qtXU[3]" ascii
    $s7  = "function dlRnG(vXikYrYH,RCtpyL,GZSvuexMX){KNYRR=vXikYrYH.split(GZSvuexMX);VNGDgiO = kMTmcytUQVcvuZSmmvk[13];for(wmpYsJjK=0;wmpYs" ascii
    $s8  = "function ybdkG(IjvDuo){return new ActiveXObject(IjvDuo);}" fullword ascii
    $s9  = "function wRqxkyZ() {var nwgS=100000;var gXOAPg = 100;return Math.random()*(nwgS-gXOAPg)+gXOAPg;}" fullword ascii
    $s10 = "function dhVSO(jMGUpaEt,dxdKE,pVRylynOzE){jMGUpaEt.open();jMGUpaEt.type = 1;jMGUpaEt.write(dxdKE);jMGUpaEt.position = 0;jMGUpaEt" ascii
    $s11 = "if (DtYqSPU==0) break;" fullword ascii
    $s12 = "JjK<RCtpyL.length;wmpYsJjK++) {VNGDgiO+=KNYRR[RCtpyL[wmpYsJjK]];}return VNGDgiO.substring(3,VNGDgiO.length);}" fullword ascii
    $s13 = "function ngiZyG(IjvDuo){return IjvDuo.ExpandEnvironmentStrings(kMTmcytUQVcvuZSmmvk[10])}" fullword ascii
    $s14 = "function dlRnG(vXikYrYH,RCtpyL,GZSvuexMX){KNYRR=vXikYrYH.split(GZSvuexMX);VNGDgiO = kMTmcytUQVcvuZSmmvk[13];for(wmpYsJjK=0;wmpYs" ascii
    $s15 = "try{DtYqSPU=bQySEtYKD(KOOMA[MbUv], wRqxkyZ() + kMTmcytUQVcvuZSmmvk[9], 1)}catch(e){}; " fullword ascii
    $s16 = "loor(Math.random()*tpJVtmMU.length));}return gsirb;}" fullword ascii
    $s17 = ", qGtruS, false);WiFTKVX.send();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}