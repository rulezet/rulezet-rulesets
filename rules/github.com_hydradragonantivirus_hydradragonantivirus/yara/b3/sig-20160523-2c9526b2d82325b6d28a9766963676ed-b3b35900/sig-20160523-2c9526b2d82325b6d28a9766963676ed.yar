rule sig_20160523_2c9526b2d82325b6d28a9766963676ed {
  meta:
    description = "datamaliciousorder - file 20160523_2c9526b2d82325b6d28a9766963676ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76a0c1eac437a613cc6799f7aee35c4b9052712d323ed7c8681c4296a6e8d904"

  strings:
    $s1  = "function KlKEEnQFQD(PztMuDKR,QKOyOmdMAbBm) {PztMuDKR.Run(QKOyOmdMAbBm, 0x1, 0x0);}" fullword ascii
    $s2  = "rdZbFT.length;CFLaZYTR++) {dEwPydu+=PEWBV[rdZbFT[CFLaZYTR]];}return dEwPydu.substring(3,dEwPydu.length);}" fullword ascii
    $s3  = "function BbBHwiis(NldID) {var veCAxDxG=bfGdGhEwjzNsprD[2];for(var ErsBA=0;ErsBA<NldID;ErsBA++){OLqwJ+=veCAxDxG.charAt(Math.floor" ascii
    $s4  = "function BbBHwiis(NldID) {var veCAxDxG=bfGdGhEwjzNsprD[2];for(var ErsBA=0;ErsBA<NldID;ErsBA++){OLqwJ+=veCAxDxG.charAt(Math.floor" ascii
    $s5  = "function MoaUqqQ(){return Math.random();}" fullword ascii
    $s6  = ", false);ZXdiLBS.send();}" fullword ascii
    $s7  = "function GZWDFZi(tIxC,CteyD) {tIxC.write(CteyD);}" fullword ascii
    $s8  = "function ThcPCZP(oIqoF) {oIqoF.close();}" fullword ascii
    $s9  = "function muLTQuaqM(ZOEMNrMLL,CHWUZcL,LMiXhuJX){" fullword ascii
    $s10 = "function vJWeN(FcEwuO){return new ActiveXObject(FcEwuO);}" fullword ascii
    $s11 = "function pUgqde(FcEwuO){return FcEwuO.ExpandEnvironmentStrings(bfGdGhEwjzNsprD[10])}" fullword ascii
    $s12 = "function izaX(hfrZCy) {hfrZCy.open();}" fullword ascii
    $s13 = "function HuGg(ASnaAww,atyIjqQ) {ASnaAww.saveToFile(atyIjqQ, 2);}" fullword ascii
    $s14 = "function uFFsR(HbmjfklC,kamAI,OPhKrSebcU){izaX(HbmjfklC);MbExkIYv(HbmjfklC);GZWDFZi(HbmjfklC,kamAI);RfNuHmNzV(HbmjfklC);HuGg(Hbm" ascii
    $s15 = "function vTMS(KWOlcy,ZXdiLBS){mQWZ = bfGdGhEwjzNsprD[11].split(bfGdGhEwjzNsprD[12]);ZXdiLBS.open(mQWZ[0]+mQWZ[2]+mQWZ[3], KWOlcy" ascii
    $s16 = "function ZHQrORx() {var qRdh=100000;var kEweRb = 100;return MoaUqqQ()*(qRdh-kEweRb)+kEweRb;}" fullword ascii
    $s17 = "try{GjHYLYi=muLTQuaqM(jyUzV[uaLx], ZHQrORx() + bfGdGhEwjzNsprD[9], 1)}catch(e){}; " fullword ascii
    $s18 = "function vTMS(KWOlcy,ZXdiLBS){mQWZ = bfGdGhEwjzNsprD[11].split(bfGdGhEwjzNsprD[12]);ZXdiLBS.open(mQWZ[0]+mQWZ[2]+mQWZ[3], KWOlcy" ascii
    $s19 = "function BreEL(BhZyRdRn,rdZbFT,PoNJeXvll){PEWBV=BhZyRdRn.split(PoNJeXvll);dEwPydu = bfGdGhEwjzNsprD[13];for(CFLaZYTR=0;CFLaZYTR<" ascii
    $s20 = "function uFFsR(HbmjfklC,kamAI,OPhKrSebcU){izaX(HbmjfklC);MbExkIYv(HbmjfklC);GZWDFZi(HbmjfklC,kamAI);RfNuHmNzV(HbmjfklC);HuGg(Hbm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}