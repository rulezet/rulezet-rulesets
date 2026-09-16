rule sig_20160523_ac57f644e05ec7eae478fa6d4e8aebde {
  meta:
    description = "datamaliciousorder - file 20160523_ac57f644e05ec7eae478fa6d4e8aebde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f7e8c182de83948f151d0c576b99a57c7262583e197d5949a55e06cafb4404"

  strings:
    $s1  = "function MKVIYvQpiI(uBivobqg,BdxNNrWQccDm) {uBivobqg.Run(BdxNNrWQccDm, 0x1, 0x0);}" fullword ascii
    $s2  = "function WMUQICuk(LkzPC) {var PvwfXTyV=MwDoJEwGRXtR[13];for(var LfMTK=0;LfMTK<LkzPC;LfMTK++){QFAbm+=PvwfXTyV.charAt(Math.floor(M" ascii
    $s3  = "function WMUQICuk(LkzPC) {var PvwfXTyV=MwDoJEwGRXtR[13];for(var LfMTK=0;LfMTK<LkzPC;LfMTK++){QFAbm+=PvwfXTyV.charAt(Math.floor(M" ascii
    $s4  = "ath.random()*PvwfXTyV.length));}return QFAbm;}" fullword ascii
    $s5  = "hqC.length;yiwpBxHZ++) {DLSpRpX+=BnCos[xjshqC[yiwpBxHZ]];}return DLSpRpX.substring(3,DLSpRpX.length);}" fullword ascii
    $s6  = "function dzyJU(SJbBLj){return new ActiveXObject(SJbBLj);}" fullword ascii
    $s7  = "function tcXBZlPr(zfPvMIAyd) {zfPvMIAyd.type=1;}" fullword ascii
    $s8  = "function nBIxcZI(){return Math.random();}" fullword ascii
    $s9  = "function dwclx(NxtIxXmh,EOITN,IZqdPcxeVj){LZYz(NxtIxXmh);tcXBZlPr(NxtIxXmh);ubLrmYV(NxtIxXmh,EOITN);KLHaMmKdl(NxtIxXmh);zacf(Nxt" ascii
    $s10 = "if(lHXV>yKAhV.length) break;" fullword ascii
    $s11 = "function fHCfd(rAUePbmz,xjshqC,WtQmmcXRW){BnCos=rAUePbmz.split(WtQmmcXRW);DLSpRpX = MwDoJEwGRXtR[12];for(yiwpBxHZ=0;yiwpBxHZ<xjs" ascii
    $s12 = "function LZYz(MqqggN) {MqqggN.open();}" fullword ascii
    $s13 = "function ubLrmYV(SJwl,AJYuF) {SJwl.write(AJYuF);}" fullword ascii
    $s14 = "function dwclx(NxtIxXmh,EOITN,IZqdPcxeVj){LZYz(NxtIxXmh);tcXBZlPr(NxtIxXmh);ubLrmYV(NxtIxXmh,EOITN);KLHaMmKdl(NxtIxXmh);zacf(Nxt" ascii
    $s15 = "function fHCfd(rAUePbmz,xjshqC,WtQmmcXRW){BnCos=rAUePbmz.split(WtQmmcXRW);DLSpRpX = MwDoJEwGRXtR[12];for(yiwpBxHZ=0;yiwpBxHZ<xjs" ascii
    $s16 = "function RBYznyr(LfbGt) {LfbGt.close();}" fullword ascii
    $s17 = "function IpDdQc(SJbBLj){return SJbBLj.ExpandEnvironmentStrings(MwDoJEwGRXtR[9])}" fullword ascii
    $s18 = "function zacf(kVkmTHu,gdWamVY) {kVkmTHu.saveToFile(gdWamVY, 2);}" fullword ascii
    $s19 = "function MWmn(hjyEhX,ScLQeYp){SvjU = MwDoJEwGRXtR[10].split(MwDoJEwGRXtR[11]);ScLQeYp.open(SvjU[0]+SvjU[2]+SvjU[3], hjyEhX, fals" ascii
    $s20 = "function KLHaMmKdl(INFiCC) {var YZZpbKFKfM=[];INFiCC.position=YZZpbKFKfM.length*(9312599-611);}" fullword ascii

  condition:
    uint16(0) == 0x0e27 and
    8 of them
}