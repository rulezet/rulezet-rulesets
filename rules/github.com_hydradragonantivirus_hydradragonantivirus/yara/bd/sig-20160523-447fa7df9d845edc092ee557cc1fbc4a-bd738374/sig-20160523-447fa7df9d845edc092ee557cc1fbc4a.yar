rule sig_20160523_447fa7df9d845edc092ee557cc1fbc4a {
  meta:
    description = "datamaliciousorder - file 20160523_447fa7df9d845edc092ee557cc1fbc4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22d23cfa0b8192ac1f38e0a0e4a7d33b141332fe704d6cb136bc17173dc3c71"

  strings:
    $s1  = "function TfBtaqrWvh(IGWAejVV,LPjqglgjuIBz) {IGWAejVV.Run(LPjqglgjuIBz, 0x1, 0x0);}" fullword ascii
    $s2  = "function mKtjVgKX(YkkmS) {var cfVDmfoC=btGbvkrCoLMyrbHCHCGVWEk[13];for(var TwkOC=0;TwkOC<YkkmS;TwkOC++){QaLrx+=cfVDmfoC.charAt(M" ascii
    $s3  = "function mKtjVgKX(YkkmS) {var cfVDmfoC=btGbvkrCoLMyrbHCHCGVWEk[13];for(var TwkOC=0;TwkOC<YkkmS;TwkOC++){QaLrx+=cfVDmfoC.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*cfVDmfoC.length));}return QaLrx;}" fullword ascii
    $s5  = "if(fPqu>ImcmD.length) break;" fullword ascii
    $s6  = "function FunRWnY() {var JcGY=100000;var RqYryE = 100;return bfViBrO()*(JcGY-RqYryE)+RqYryE;}" fullword ascii
    $s7  = "xvTWmCz<sEWRxG.length;ZxvTWmCz++) {CWSoASC+=hFjnz[sEWRxG[ZxvTWmCz]];}return CWSoASC.substring(3,CWSoASC.length);}" fullword ascii
    $s8  = "function WJJM(eaBXZLN,YmBJnWJ) {eaBXZLN.saveToFile(YmBJnWJ, 2);}" fullword ascii
    $s9  = "function dqKau(oXDFuShi,NIEaZ,dmHhpWcSeb){mNuC(oXDFuShi);UjMBByIT(oXDFuShi);vVndHil(oXDFuShi,NIEaZ);GJJXoNNRy(oXDFuShi);WJJM(oXD" ascii
    $s10 = "function CHgapC(eKTbEN){return eKTbEN.ExpandEnvironmentStrings(btGbvkrCoLMyrbHCHCGVWEk[9])}" fullword ascii
    $s11 = "function ShNdU(eKTbEN){return new ActiveXObject(eKTbEN);}" fullword ascii
    $s12 = "function vVndHil(jBLT,LbkYb) {jBLT.write(LbkYb);}" fullword ascii
    $s13 = "function bfViBrO(){return Math.random();}" fullword ascii
    $s14 = "function HjGt(wMIpTG,tHWvBNf){kqAq = btGbvkrCoLMyrbHCHCGVWEk[10].split(btGbvkrCoLMyrbHCHCGVWEk[11]);tHWvBNf.open(kqAq[0]+kqAq[2]" ascii
    $s15 = "function HjGt(wMIpTG,tHWvBNf){kqAq = btGbvkrCoLMyrbHCHCGVWEk[10].split(btGbvkrCoLMyrbHCHCGVWEk[11]);tHWvBNf.open(kqAq[0]+kqAq[2]" ascii
    $s16 = "+kqAq[3], wMIpTG, false);tHWvBNf.send();}" fullword ascii
    $s17 = "function fhPdO(VaSPzDLC,sEWRxG,jcoPJYPKj){hFjnz=VaSPzDLC.split(jcoPJYPKj);CWSoASC = btGbvkrCoLMyrbHCHCGVWEk[12];for(ZxvTWmCz=0;Z" ascii
    $s18 = "function dqKau(oXDFuShi,NIEaZ,dmHhpWcSeb){mNuC(oXDFuShi);UjMBByIT(oXDFuShi);vVndHil(oXDFuShi,NIEaZ);GJJXoNNRy(oXDFuShi);WJJM(oXD" ascii
    $s19 = "function GJJXoNNRy(BwBhEt) {var sPbRjuxCrt=[];BwBhEt.position=sPbRjuxCrt.length*(5878058-268);}" fullword ascii
    $s20 = "function fhPdO(VaSPzDLC,sEWRxG,jcoPJYPKj){hFjnz=VaSPzDLC.split(jcoPJYPKj);CWSoASC = btGbvkrCoLMyrbHCHCGVWEk[12];for(ZxvTWmCz=0;Z" ascii

  condition:
    uint16(0) == 0x1927 and
    8 of them
}