rule sig_20160520_408ba3ba3046ac50c4a14be2bb0c4090 {
  meta:
    description = "datamaliciousorder - file 20160520_408ba3ba3046ac50c4a14be2bb0c4090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e6fcbd1ba611ea8ad1a3e70ef7eb299f9ab1e6f5f02236ea9d9222e61e291c2"

  strings:
    $s1  = "function JecNbDnF(lYave) {var mXUYSgnL=bqqRbDhiSOWuQQdpL[2];for(var NimJy=0;NimJy<lYave;NimJy++){hbKVI+=mXUYSgnL.charAt(Math.flo" ascii
    $s2  = "function JecNbDnF(lYave) {var mXUYSgnL=bqqRbDhiSOWuQQdpL[2];for(var NimJy=0;NimJy<lYave;NimJy++){hbKVI+=mXUYSgnL.charAt(Math.flo" ascii
    $s3  = "function ObHPB(UiWmhjeU,txCXJ,iktHcsHsqU){UiWmhjeU.open();UiWmhjeU.type = 1;UiWmhjeU.write(txCXJ);UiWmhjeU.position = 0;UiWmhjeU" ascii
    $s4  = "function KGAaw(ZeMZolvm,vBNzUe,aGKzSYoSB){iTajO=ZeMZolvm.split(aGKzSYoSB);mdsQncW = bqqRbDhiSOWuQQdpL[13];for(sFMMhhnL=0;sFMMhhn" ascii
    $s5  = "function LvKh(dWuWJy,hGahida){CiEi = bqqRbDhiSOWuQQdpL[11].split(bqqRbDhiSOWuQQdpL[12]);hGahida.open(CiEi[0]+CiEi[2]+CiEi[3], dW" ascii
    $s6  = "function LvKh(dWuWJy,hGahida){CiEi = bqqRbDhiSOWuQQdpL[11].split(bqqRbDhiSOWuQQdpL[12]);hGahida.open(CiEi[0]+CiEi[2]+CiEi[3], dW" ascii
    $s7  = "function FloDYJR() {var wlEw=100000;var zBQbrH = 100;return Math.random()*(wlEw-zBQbrH)+zBQbrH;}" fullword ascii
    $s8  = "function ObHPB(UiWmhjeU,txCXJ,iktHcsHsqU){UiWmhjeU.open();UiWmhjeU.type = 1;UiWmhjeU.write(txCXJ);UiWmhjeU.position = 0;UiWmhjeU" ascii
    $s9  = "function SMimzs(HEGUEY){return HEGUEY.ExpandEnvironmentStrings(bqqRbDhiSOWuQQdpL[10])}" fullword ascii
    $s10 = "function yNwidaWSs(Idxdfpdvh,Dngitiu,YJsYWYVd){" fullword ascii
    $s11 = "L<vBNzUe.length;sFMMhhnL++) {mdsQncW+=iTajO[vBNzUe[sFMMhhnL]];}return mdsQncW.substring(3,mdsQncW.length);}" fullword ascii
    $s12 = "function KGAaw(ZeMZolvm,vBNzUe,aGKzSYoSB){iTajO=ZeMZolvm.split(aGKzSYoSB);mdsQncW = bqqRbDhiSOWuQQdpL[13];for(sFMMhhnL=0;sFMMhhn" ascii
    $s13 = "uWJy, false);hGahida.send();}" fullword ascii
    $s14 = "function GsBfy(HEGUEY){return new ActiveXObject(HEGUEY);}" fullword ascii
    $s15 = "try{yNwidaWSs(CsToQ[bnKc], FloDYJR() + bqqRbDhiSOWuQQdpL[9], 1)}catch(e){}; " fullword ascii
    $s16 = "or(Math.random()*mXUYSgnL.length));}return hbKVI;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}