rule sig_20160520_46c0595a36824e6f1ca49baa663660f8 {
  meta:
    description = "datamaliciousorder - file 20160520_46c0595a36824e6f1ca49baa663660f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26197a7a5f9c73ff4742c6115f8f545561c0fbeb4f255e6072a8b8172b20356f"

  strings:
    $s1  = "function tHcsHsqU(LvKhd) {var WuWJyhGa=ikARewRjOu[2];for(var hidaC=0;hidaC<LvKhd;hidaC++){iEiNs+=WuWJyhGa.charAt(Math.floor(Math" ascii
    $s2  = "function tHcsHsqU(LvKhd) {var WuWJyhGa=ikARewRjOu[2];for(var hidaC=0;hidaC<LvKhd;hidaC++){iEiNs+=WuWJyhGa.charAt(Math.floor(Math" ascii
    $s3  = "function MrBLDOORS(KGAawZeMZ,olvmvBN,zUeaGKzS){" fullword ascii
    $s4  = ".random()*WuWJyhGa.length));}return iEiNs;}" fullword ascii
    $s5  = "function aQKnW(dTDiiIfj,knJWO,vHVZrSevMI){dTDiiIfj.open();dTDiiIfj.type = 1;dTDiiIfj.write(knJWO);dTDiiIfj.position = 0;dTDiiIfj" ascii
    $s6  = "function jKVMgG(HcnoCX){return HcnoCX.ExpandEnvironmentStrings(ikARewRjOu[10])}" fullword ascii
    $s7  = "function UjRU(rRtUTA,BzyOcdE){Mhxk = ikARewRjOu[11].split(ikARewRjOu[12]);BzyOcdE.open(Mhxk[0]+Mhxk[2]+Mhxk[3], rRtUTA, false);B" ascii
    $s8  = "if (mkbxKva==0) break;" fullword ascii
    $s9  = "function PBUiWmh() {var jeUt=100000;var xCXJik = 100;return Math.random()*(jeUt-xCXJik)+xCXJik;}" fullword ascii
    $s10 = "function bMWhA(HcnoCX){return new ActiveXObject(HcnoCX);}" fullword ascii
    $s11 = "try{mkbxKva=MrBLDOORS(wPObH[aSae], PBUiWmh() + ikARewRjOu[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function UjRU(rRtUTA,BzyOcdE){Mhxk = ikARewRjOu[11].split(ikARewRjOu[12]);BzyOcdE.open(Mhxk[0]+Mhxk[2]+Mhxk[3], rRtUTA, false);B" ascii
    $s13 = "t.length;nuzyyKfx++) {tAtLjYm+=hcVAf[CFuywt[nuzyyKfx]];}return tAtLjYm.substring(3,tAtLjYm.length);}" fullword ascii
    $s14 = "function aQKnW(dTDiiIfj,knJWO,vHVZrSevMI){dTDiiIfj.open();dTDiiIfj.type = 1;dTDiiIfj.write(knJWO);dTDiiIfj.position = 0;dTDiiIfj" ascii
    $s15 = "function PHNqv(TGUEsCAI,CFuywt,osyYrjHZr){hcVAf=TGUEsCAI.split(osyYrjHZr);tAtLjYm = ikARewRjOu[13];for(nuzyyKfx=0;nuzyyKfx<CFuyw" ascii
    $s16 = "function PHNqv(TGUEsCAI,CFuywt,osyYrjHZr){hcVAf=TGUEsCAI.split(osyYrjHZr);tAtLjYm = ikARewRjOu[13];for(nuzyyKfx=0;nuzyyKfx<CFuyw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}