rule sig_20160527_2ffe7f68481eb7a857b58fdbad9d286d {
  meta:
    description = "datamaliciousorder - file 20160527_2ffe7f68481eb7a857b58fdbad9d286d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b495dfff3be34a901c9ea321f12283365fe8f58ce0770d2afce8cceb641fc6c"

  strings:
    $s1  = "function SmvPaDetC() {return WScript;}function GNKNs(){return xGyDZymCGz.ExpandEnvironmentStrings(EAlekgfPP())}" fullword ascii
    $s2  = "function gRXNVbCbAJNIDn(jQVRUrTByCrJlZEMz,WDGXfifaMbivjFSBIjv){return jQVRUrTByCrJlZEMz.charAt(WDGXfifaMbivjFSBIjv);}" fullword ascii
    $s3  = "var xGyDZymCGz=function(){return SmvPaDetC().CreateObject(EJFVBmSB[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s4  = "e if (fjsNrcJyoaBl == 64) gXNFNTUBLQqiKraOm += xmebqjv(VlgwSvrjgQERSVM, ISgEcSZ);else gXNFNTUBLQqiKraOm += hILNG(VlgwSvrjgQERSVM" ascii
    $s5  = "function dyxFGUisNtupoY(RJfbLA,hhcBjdxXhGaiGG,msetukTvkSYER){oiyfxyz=RJfbLA.split(msetukTvkSYER);JMTeFxDiZLzLC = EJFVBmSB[14];fo" ascii
    $s6  = "function hILNG(YeFOKTVtjZIRYshJSP,ItqbZtDxPkdljupwbAIwdJv,sZMfAAcb){return String.fromCharCode(YeFOKTVtjZIRYshJSP,ItqbZtDxPkdlju" ascii
    $s7  = "function mHGQvyUtBxiCR(nKOQuW,iIXAckffFy) {var NigaFdtIR=[EJFVBmSB[15]];nKOQuW[NigaFdtIR[0]](iIXAckffFy,0x1,0x0)}" fullword ascii
    $s8  = "function hILNG(YeFOKTVtjZIRYshJSP,ItqbZtDxPkdljupwbAIwdJv,sZMfAAcb){return String.fromCharCode(YeFOKTVtjZIRYshJSP,ItqbZtDxPkdlju" ascii
    $s9  = "r(UJSBHwaIQqc=0;UJSBHwaIQqc<hhcBjdxXhGaiGG.length;UJSBHwaIQqc++) {JMTeFxDiZLzLC+=oiyfxyz[hhcBjdxXhGaiGG[UJSBHwaIQqc]];}return JM" ascii
    $s10 = "function dyxFGUisNtupoY(RJfbLA,hhcBjdxXhGaiGG,msetukTvkSYER){oiyfxyz=RJfbLA.split(msetukTvkSYER);JMTeFxDiZLzLC = EJFVBmSB[14];fo" ascii
    $s11 = "function e(CtjtcKbqfBNOnfy){return String.fromCharCode(CtjtcKbqfBNOnfy);}" fullword ascii
    $s12 = "function EAlekgfPP(){return dyxFGUisNtupoY(EJFVBmSB[8],[1,5,7],EJFVBmSB[9]);}" fullword ascii
    $s13 = "92)+EJFVBmSB[4],true);" fullword ascii
    $s14 = "function JoofsJRSC(){return dyxFGUisNtupoY(EJFVBmSB[10],[2,4,8,10],EJFVBmSB[11]);}" fullword ascii
    $s15 = "function olAtash(ixNOKLzcYJdSdYUjdsqbIK,pqYQFky){return ixNOKLzcYJdSdYUjdsqbIK.indexOf(pqYQFky);}" fullword ascii
    $s16 = ", ISgEcSZ, uLXOnljopnigIAbbtYYQR);} while (kARapaFNHEBvLoUFPPJN < UzhHpmelLJvsp.length);return gXNFNTUBLQqiKraOm;}" fullword ascii
    $s17 = "function uTrNR(UzhHpmelLJvsp) {var hyWOajXzJlqaxELX = chWBSrO.join(EJFVBmSB[6]);var VlgwSvrjgQERSVM, ISgEcSZ, uLXOnljopnigIAbbtY" ascii
    $s18 = "function uTrNR(UzhHpmelLJvsp) {var hyWOajXzJlqaxELX = chWBSrO.join(EJFVBmSB[6]);var VlgwSvrjgQERSVM, ISgEcSZ, uLXOnljopnigIAbbtY" ascii
    $s19 = "function xmebqjv(BYhSCdxOMCzQSUscwuA,IYAwSwsgfiiscUdfUoq){return String.fromCharCode(BYhSCdxOMCzQSUscwuA,IYAwSwsgfiiscUdfUoq);}" fullword ascii
    $s20 = "function MdQBS(){return dyxFGUisNtupoY(EJFVBmSB[12],[0,3,6],EJFVBmSB[13]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}