rule sig_20160523_b5269f64a64d4ef2c2d5b5a6539de2a7 {
  meta:
    description = "datamaliciousorder - file 20160523_b5269f64a64d4ef2c2d5b5a6539de2a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a20293df10299180697d24d07db90a2c8b44e810039472db8bb452732221d5b"

  strings:
    $s1  = "function gQwCtGDCbo() {return/*mlkwSPrYNFTTvMKmRHtFnAcuCeosmzKakGFToppxdSHVucnsyHhwkFSxOumOgZVpVDcimZmqusKhKNAPjpnnOJVhZodREnumr" ascii
    $s2  = "function RyktwbfokC(bdYmUUob,RxkkCZuKxiHg) {bdYmUUob.Run(RxkkCZuKxiHg, 0x1, 0x0);}" fullword ascii
    $s3  = "function wiRCBgH(){return Math.random();}" fullword ascii
    $s4  = "function KwyTLTv() {var YQRD=100000;var lqFyCq = 100;return wiRCBgH()*(YQRD-lqFyCq)+lqFyCq;}" fullword ascii
    $s5  = "function IhYVOxLt(Rvzag) {var LUzLsNxN=UFOvhHGDBXWXzVrCPuH[13];for(var yCcTA=0;yCcTA<Rvzag;yCcTA++){tqbBV+=LUzLsNxN.charAt(Math." ascii
    $s6  = "function IhYVOxLt(Rvzag) {var LUzLsNxN=UFOvhHGDBXWXzVrCPuH[13];for(var yCcTA=0;yCcTA<Rvzag;yCcTA++){tqbBV+=LUzLsNxN.charAt(Math." ascii
    $s7  = "function MzsK(ASVaYJ,xYKFUDQ){ZfnN = UFOvhHGDBXWXzVrCPuH[10].split(UFOvhHGDBXWXzVrCPuH[11]);xYKFUDQ.open(ZfnN[0]+ZfnN[2]+ZfnN[3]" ascii
    $s8  = "floor(Math.random()*LUzLsNxN.length));}return tqbBV;}" fullword ascii
    $s9  = "wjs<FugzIV.length;VvTacwjs++) {RagmKYM+=BLaRa[FugzIV[VvTacwjs]];}return RagmKYM.substring(3,RagmKYM.length);}" fullword ascii
    $s10 = "function gQwCtGDCbo() {return/*mlkwSPrYNFTTvMKmRHtFnAcuCeosmzKakGFToppxdSHVucnsyHhwkFSxOumOgZVpVDcimZmqusKhKNAPjpnnOJVhZodREnumr" ascii
    $s11 = "if(Ccqb>iWHGl.length) break;" fullword ascii
    $s12 = "function WNwwvPl(lLhGS) {lLhGS.close();}" fullword ascii
    $s13 = "function MzsK(ASVaYJ,xYKFUDQ){ZfnN = UFOvhHGDBXWXzVrCPuH[10].split(UFOvhHGDBXWXzVrCPuH[11]);xYKFUDQ.open(ZfnN[0]+ZfnN[2]+ZfnN[3]" ascii
    $s14 = "function QlOR(ZAxrHRp,tAyAdsS) {ZAxrHRp.saveToFile(tAyAdsS, 2);}" fullword ascii
    $s15 = ", ASVaYJ, false);xYKFUDQ.send();}" fullword ascii
    $s16 = "function XYxMu(mGZWRPLQ,FugzIV,COpWGstrI){BLaRa=mGZWRPLQ.split(COpWGstrI);RagmKYM = UFOvhHGDBXWXzVrCPuH[12];for(VvTacwjs=0;VvTac" ascii
    $s17 = "function hwgHdf(rwWfhn){return rwWfhn.ExpandEnvironmentStrings(UFOvhHGDBXWXzVrCPuH[9])}" fullword ascii
    $s18 = "function XYxMu(mGZWRPLQ,FugzIV,COpWGstrI){BLaRa=mGZWRPLQ.split(COpWGstrI);RagmKYM = UFOvhHGDBXWXzVrCPuH[12];for(VvTacwjs=0;VvTac" ascii
    $s19 = "function PBGQu(MiYMjast,gWCBB,GYUmzplJzA){GlUa(MiYMjast);TTBMzRpf(MiYMjast);EuqyFDL(MiYMjast,gWCBB);SaBhXBnDn(MiYMjast);QlOR(MiY" ascii
    $s20 = "function PBGQu(MiYMjast,gWCBB,GYUmzplJzA){GlUa(MiYMjast);TTBMzRpf(MiYMjast);EuqyFDL(MiYMjast,gWCBB);SaBhXBnDn(MiYMjast);QlOR(MiY" ascii

  condition:
    uint16(0) == 0x1827 and
    8 of them
}