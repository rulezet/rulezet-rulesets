rule sig_20160520_a00ab5a09e2cf794752aef617276105c {
  meta:
    description = "datamaliciousorder - file 20160520_a00ab5a09e2cf794752aef617276105c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e5f40d3b3210b5665835cdbd001ee472d383f2f727ea61b7a89ac0e3395bd89"

  strings:
    $s1  = "function jyUfklhA(mMkDL) {var infIccyz=EGUEMw[2];for(var zPBkf=0;zPBkf<mMkDL;zPBkf++){kFmZA+=infIccyz.charAt(Math.floor(Math.ran" ascii
    $s2  = "function jyUfklhA(mMkDL) {var infIccyz=EGUEMw[2];for(var zPBkf=0;zPBkf<mMkDL;zPBkf++){kFmZA+=infIccyz.charAt(Math.floor(Math.ran" ascii
    $s3  = "function DHGXLJ(AhecmT){return AhecmT.ExpandEnvironmentStrings(EGUEMw[10])}" fullword ascii
    $s4  = "function iVRDE(oGzAeTin,PKOJtK,dgpXmxBcb){BpTLM=oGzAeTin.split(dgpXmxBcb);xpgBocl = EGUEMw[13];for(YCeHCqIP=0;YCeHCqIP<PKOJtK.le" ascii
    $s5  = "function ckDL(CXTisi,Ahuukah){NiHF = EGUEMw[11].split(EGUEMw[12]);Ahuukah.open(NiHF[0]+NiHF[2]+NiHF[3], CXTisi, false);Ahuukah.s" ascii
    $s6  = "function lYGfa(AhecmT){return new ActiveXObject(AhecmT);}" fullword ascii
    $s7  = "function KMthUGDwA(NYRlFBgTm,kviyVqP,IiUbIVOB){" fullword ascii
    $s8  = "function ckDL(CXTisi,Ahuukah){NiHF = EGUEMw[11].split(EGUEMw[12]);Ahuukah.open(NiHF[0]+NiHF[2]+NiHF[3], CXTisi, false);Ahuukah.s" ascii
    $s9  = "dom()*infIccyz.length));}return kFmZA;}" fullword ascii
    $s10 = "function iVRDE(oGzAeTin,PKOJtK,dgpXmxBcb){BpTLM=oGzAeTin.split(dgpXmxBcb);xpgBocl = EGUEMw[13];for(YCeHCqIP=0;YCeHCqIP<PKOJtK.le" ascii
    $s11 = "function TyfqD(NozMqLRU,nJhZi,UQyiBHrPsa){NozMqLRU.open();NozMqLRU.type = 1;NozMqLRU.write(nJhZi);NozMqLRU.position = 0;NozMqLRU" ascii
    $s12 = "function TyfqD(NozMqLRU,nJhZi,UQyiBHrPsa){NozMqLRU.open();NozMqLRU.type = 1;NozMqLRU.write(nJhZi);NozMqLRU.position = 0;NozMqLRU" ascii
    $s13 = "function miaYDUB() {var lRMy=100000;var vsjWLa = 100;return Math.random()*(lRMy-vsjWLa)+vsjWLa;}" fullword ascii
    $s14 = "if (MvyrbyZ==0) break;" fullword ascii
    $s15 = "ngth;YCeHCqIP++) {xpgBocl+=BpTLM[PKOJtK[YCeHCqIP]];}return xpgBocl.substring(3,xpgBocl.length);}" fullword ascii
    $s16 = "try{MvyrbyZ=KMthUGDwA(RZFpV[RHLU], miaYDUB() + EGUEMw[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}