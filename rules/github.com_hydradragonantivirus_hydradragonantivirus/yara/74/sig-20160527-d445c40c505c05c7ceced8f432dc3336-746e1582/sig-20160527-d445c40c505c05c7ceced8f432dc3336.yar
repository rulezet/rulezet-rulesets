rule sig_20160527_d445c40c505c05c7ceced8f432dc3336 {
  meta:
    description = "datamaliciousorder - file 20160527_d445c40c505c05c7ceced8f432dc3336.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1960394982917760cbf917a63b435196c94ecade8f8175c4edba18ddbde5c84d"

  strings:
    $s1  = "function UQmDYUDuXhLM() {return WScript;}function YtrPXMxNLniM(){return sPrtHbq.ExpandEnvironmentStrings(KAMabdpEtI())}" fullword ascii
    $s2  = "function ULiTDbJJvHJzAuRuVHKPlZd(IxOsDmhdao,fJSegGjIC){return IxOsDmhdao.charAt(fJSegGjIC);}" fullword ascii
    $s3  = "function lMGyxarHcjHdrGtWm(sTPyGYylwGfMU,UfAioPbtxngMHaUUy,yOMSoiKjKMLMlmZFNFQiPH){return String.fromCharCode(sTPyGYylwGfMU,UfAi" ascii
    $s4  = "QSvrjGM += ODGUtBmYac(wjuANRlRjpJSn, lcDquMmzACouR);else tbyijbPQSvrjGM += lMGyxarHcjHdrGtWm(wjuANRlRjpJSn, lcDquMmzACouR, QCjBQ" ascii
    $s5  = "[14];for(wcTzjFGYMBT=0;wcTzjFGYMBT<CWoiSkrnN.length;wcTzjFGYMBT++) {ZbHrTtZZEZDutC+=fugnFJp[CWoiSkrnN[wcTzjFGYMBT]];}return ZbHr" ascii
    $s6  = "function kSKveSTcoVbOHVWozNrXE(QaaVGGXDxrqkOvjScTxwt,tWXibbhvuBUIDvyMpF){return QaaVGGXDxrqkOvjScTxwt.indexOf(tWXibbhvuBUIDvyMpF" ascii
    $s7  = "function nWfxbDmGzB(dBEVQnlNLUKmHE,LxxFIO) {var RywPlUOBz=[KdhNqfXWo[15]];dBEVQnlNLUKmHE[RywPlUOBz[0]](LxxFIO,0x1,0x0)}" fullword ascii
    $s8  = "function ODGUtBmYac(pVouUXUpstcfeCbJEDaFGO,fPuBrJOkwgcZCUjikXD){return String.fromCharCode(pVouUXUpstcfeCbJEDaFGO,fPuBrJOkwgcZCU" ascii
    $s9  = "NqfXWo[4],true);" fullword ascii
    $s10 = ");} while (mPRJfbejAFxebYJrVOyaB < eagZHegBfemeR.length);return tbyijbPQSvrjGM;}" fullword ascii
    $s11 = "var nNmqHesM=function(){return new ActiveXObject(KdhNqfXWo[0]);}();" fullword ascii
    $s12 = "function kSKveSTcoVbOHVWozNrXE(QaaVGGXDxrqkOvjScTxwt,tWXibbhvuBUIDvyMpF){return QaaVGGXDxrqkOvjScTxwt.indexOf(tWXibbhvuBUIDvyMpF" ascii
    $s13 = " lClrw>> 8 & 0xff;QCjBQ = lClrw & 0xff;if (cQkyWttM == 64) tbyijbPQSvrjGM += F(wjuANRlRjpJSn);else if (QLOrnKUAXo == 64) tbyijbP" ascii
    $s14 = "function iSYJR(eagZHegBfemeR) {var cNLXXnesMQWOORo = sCcpIcsEBrmYktCQZFQp.join(KdhNqfXWo[6]);var wjuANRlRjpJSn, lcDquMmzACouR, Q" ascii
    $s15 = "function KAMabdpEtI(){return vrvNeXCz(KdhNqfXWo[8],[1,5,7],KdhNqfXWo[9]);}" fullword ascii
    $s16 = "function ODGUtBmYac(pVouUXUpstcfeCbJEDaFGO,fPuBrJOkwgcZCUjikXD){return String.fromCharCode(pVouUXUpstcfeCbJEDaFGO,fPuBrJOkwgcZCU" ascii
    $s17 = "function PDXTzBNexHxbC(){return vrvNeXCz(KdhNqfXWo[12],[0,3,6],KdhNqfXWo[13]);}" fullword ascii
    $s18 = "function lMGyxarHcjHdrGtWm(sTPyGYylwGfMU,UfAioPbtxngMHaUUy,yOMSoiKjKMLMlmZFNFQiPH){return String.fromCharCode(sTPyGYylwGfMU,UfAi" ascii
    $s19 = "function F(WjIPsLeZcCZVmTx){return String.fromCharCode(WjIPsLeZcCZVmTx);}" fullword ascii
    $s20 = "function fuNccdCGYm(){return vrvNeXCz(KdhNqfXWo[10],[2,4,8,10],KdhNqfXWo[11]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}