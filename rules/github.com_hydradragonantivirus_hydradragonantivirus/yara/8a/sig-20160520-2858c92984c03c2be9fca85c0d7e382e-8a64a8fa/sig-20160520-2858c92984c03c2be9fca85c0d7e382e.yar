rule sig_20160520_2858c92984c03c2be9fca85c0d7e382e {
  meta:
    description = "datamaliciousorder - file 20160520_2858c92984c03c2be9fca85c0d7e382e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3301502e621d174133a6acbccd44d0e0b8c0dadfd7b3bc668129efc1c4ee2f"

  strings:
    $s1  = "function uywtosyY(rjHZr) {var nuzyyKfx=qGsvQKApcpkIljUfKWfeUf[2];for(var hcVAf=0;hcVAf<rjHZr;hcVAf++){tAtLj+=nuzyyKfx.charAt(Mat" ascii
    $s2  = "function uywtosyY(rjHZr) {var nuzyyKfx=qGsvQKApcpkIljUfKWfeUf[2];for(var hcVAf=0;hcVAf<rjHZr;hcVAf++){tAtLj+=nuzyyKfx.charAt(Mat" ascii
    $s3  = "function cuXjv(DOZbFy){return new ActiveXObject(DOZbFy);}" fullword ascii
    $s4  = "try{GbXcMBG=WSNDwvtEg(ClVUK[RVhL], qdPHNqv() + qGsvQKApcpkIljUfKWfeUf[9], 1)}catch(e){}; " fullword ascii
    $s5  = "MoP[3], JTNcJe, false);CfhzLPO.send();}" fullword ascii
    $s6  = "function EnAnS(wktRbBvm,vWyou,ufIruxGeUd){wktRbBvm.open();wktRbBvm.type = 1;wktRbBvm.write(vWyou);wktRbBvm.position = 0;wktRbBvm" ascii
    $s7  = "h.floor(Math.random()*nuzyyKfx.length));}return tAtLj;}" fullword ascii
    $s8  = "function EnAnS(wktRbBvm,vWyou,ufIruxGeUd){wktRbBvm.open();wktRbBvm.type = 1;wktRbBvm.write(vWyou);wktRbBvm.position = 0;wktRbBvm" ascii
    $s9  = "function eAotZV(DOZbFy){return DOZbFy.ExpandEnvironmentStrings(qGsvQKApcpkIljUfKWfeUf[10])}" fullword ascii
    $s10 = "if (GbXcMBG==0) break;" fullword ascii
    $s11 = "function UZsd(JTNcJe,CfhzLPO){vMoP = qGsvQKApcpkIljUfKWfeUf[11].split(qGsvQKApcpkIljUfKWfeUf[12]);CfhzLPO.open(vMoP[0]+vMoP[2]+v" ascii
    $s12 = "function WSNDwvtEg(RymeDaaoQ,fiKLYDp,RpCCorYw){" fullword ascii
    $s13 = "function UZsd(JTNcJe,CfhzLPO){vMoP = qGsvQKApcpkIljUfKWfeUf[11].split(qGsvQKApcpkIljUfKWfeUf[12]);CfhzLPO.open(vMoP[0]+vMoP[2]+v" ascii
    $s14 = "function jrqQD(kPwxktGw,dvRGaN,dEMMMwzlS){KzCaa=kPwxktGw.split(dEMMMwzlS);zvDieAT = qGsvQKApcpkIljUfKWfeUf[13];for(NYBTHuBO=0;NY" ascii
    $s15 = "function jrqQD(kPwxktGw,dvRGaN,dEMMMwzlS){KzCaa=kPwxktGw.split(dEMMMwzlS);zvDieAT = qGsvQKApcpkIljUfKWfeUf[13];for(NYBTHuBO=0;NY" ascii
    $s16 = "function qdPHNqv() {var TGUE=100000;var sCAICF = 100;return Math.random()*(TGUE-sCAICF)+sCAICF;}" fullword ascii
    $s17 = "BTHuBO<dvRGaN.length;NYBTHuBO++) {zvDieAT+=KzCaa[dvRGaN[NYBTHuBO]];}return zvDieAT.substring(3,zvDieAT.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}