rule sig_20160523_269defa3696df4c2f09115bc1dcb3b93 {
  meta:
    description = "datamaliciousorder - file 20160523_269defa3696df4c2f09115bc1dcb3b93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a4771587c630f7b19745bc949d80719da45cc10b55bb138873ccab834e7f49"

  strings:
    $s1  = "function dNifToGvPe(pESpORlM,lgREHnqkEpWc) {pESpORlM.Run(lgREHnqkEpWc, 0x1, 0x0);}" fullword ascii
    $s2  = "function sEAzZmjgkr() {return/*cznxqjgjrGbbNOsgzsyKIpgnYpcygtBgpRvKCVAUdxDggKcUQMUjoHnVrSDlDJTiOPWitpLQileRUCmeTRzZnYqemxSUJSgkw" ascii
    $s3  = "function SfEvbxcA(DceDz) {var yDSzVEGo=iPyylEJSsQAapHXfH[13];for(var ulAfi=0;ulAfi<DceDz;ulAfi++){rTrdH+=yDSzVEGo.charAt(Math.fl" ascii
    $s4  = "function SfEvbxcA(DceDz) {var yDSzVEGo=iPyylEJSsQAapHXfH[13];for(var ulAfi=0;ulAfi<DceDz;ulAfi++){rTrdH+=yDSzVEGo.charAt(Math.fl" ascii
    $s5  = "function dIxNV(EVkTWcAf,PDkTF,hKLCSAMvmV){Yngm(EVkTWcAf);fnKQlSKO(EVkTWcAf);vXrPrvl(EVkTWcAf,PDkTF);BFqwDBXOh(EVkTWcAf);pzHr(EVk" ascii
    $s6  = "function fnKQlSKO(RLKdJqAwF) {RLKdJqAwF.type=1;}" fullword ascii
    $s7  = "function SjaW(VwOxBK,pFYbHdB){MqrE = iPyylEJSsQAapHXfH[10].split(iPyylEJSsQAapHXfH[11]);pFYbHdB.open(MqrE[0]+MqrE[2]+MqrE[3], Vw" ascii
    $s8  = "function EbRgysF(DViUN) {DViUN.close();}" fullword ascii
    $s9  = "function ypHan(sNhxQkXs,QlBUkM,ahKglCZZJ){NJNBt=sNhxQkXs.split(ahKglCZZJ);oYLpSDW = iPyylEJSsQAapHXfH[12];for(RpLRJuuH=0;RpLRJuu" ascii
    $s10 = "oor(Math.random()*yDSzVEGo.length));}return rTrdH;}" fullword ascii
    $s11 = "function SjaW(VwOxBK,pFYbHdB){MqrE = iPyylEJSsQAapHXfH[10].split(iPyylEJSsQAapHXfH[11]);pFYbHdB.open(MqrE[0]+MqrE[2]+MqrE[3], Vw" ascii
    $s12 = "function Yngm(Lhwary) {Lhwary.open();}" fullword ascii
    $s13 = "function vXrPrvl(PikM,iYiQD) {PikM.write(iYiQD);}" fullword ascii
    $s14 = "function dIxNV(EVkTWcAf,PDkTF,hKLCSAMvmV){Yngm(EVkTWcAf);fnKQlSKO(EVkTWcAf);vXrPrvl(EVkTWcAf,PDkTF);BFqwDBXOh(EVkTWcAf);pzHr(EVk" ascii
    $s15 = "function HTSkGMJ(){return Math.random();}" fullword ascii
    $s16 = "H<QlBUkM.length;RpLRJuuH++) {oYLpSDW+=NJNBt[QlBUkM[RpLRJuuH]];}return oYLpSDW.substring(3,oYLpSDW.length);}" fullword ascii
    $s17 = "function BFqwDBXOh(MPFkxX) {var ZFVfMdmeFf=[];MPFkxX.position=ZFVfMdmeFf.length*(9363032-143);}" fullword ascii
    $s18 = "if(rJKD>HYVHr.length) break;" fullword ascii
    $s19 = "OxBK, false);pFYbHdB.send();}" fullword ascii
    $s20 = "function ypHan(sNhxQkXs,QlBUkM,ahKglCZZJ){NJNBt=sNhxQkXs.split(ahKglCZZJ);oYLpSDW = iPyylEJSsQAapHXfH[12];for(RpLRJuuH=0;RpLRJuu" ascii

  condition:
    uint16(0) == 0x1827 and
    8 of them
}