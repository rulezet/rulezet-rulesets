rule sig_20160531_5ce3581e4f6077a34066d040f9d9b804 {
  meta:
    description = "datamaliciousorder - file 20160531_5ce3581e4f6077a34066d040f9d9b804.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1cdfc66164024075b1245b346355a2fd952636cf4da6e3978d093b35b2d86a5"

  strings:
    $s1  = "var pJnzqZpYuwkYS=function(){return WScript.CreateObject(TnwBzTQJTXQcPXLf[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function KcMFcJ(NtCNXSIsPuRXN,QMyPXWeOnkDbW){return NtCNXSIsPuRXN.charAt(QMyPXWeOnkDbW);}" fullword ascii
    $s3  = "(VHmCLbnReq,0x1,0x0)}function EsEDXDifvRpCHJ(vEpWdoHTOhhKW,AuysbqqWORBjcO,DImxBumr){var CRpljyE=vEpWdoHTOhhKW.createtextfile(Auy" ascii
    $s4  = "function QfAcfi(){return pJnzqZpYuwkYS.ExpandEnvironmentStrings(NkbdwCs())}" fullword ascii
    $s5  = "function crbVWUyMtdcEJwhKWo(bIbkDMhYaxgefYGoiowF,QaGJGPXYRqPIkvrbNVC){return bIbkDMhYaxgefYGoiowF.indexOf(QaGJGPXYRqPIkvrbNVC);}" ascii
    $s6  = "function oIIYNufhKZxFX(mQeQbmzyfLqSK) {var UcsOFIITdha = yprUtIbWr.join(TnwBzTQJTXQcPXLf[7]);var XfHwIdBWRciJnxxJqemwBPLc, AVqDK" ascii
    $s7  = "function yYuHwpXvNcENcs(pkAKMinWbtaeZZM,plxoGpioHErfeT,eoblfMpjyiwTcUAJkriT){return String.fromCharCode(pkAKMinWbtaeZZM,plxoGpio" ascii
    $s8  = ";LVkXVrzW<YRieGXYyjH.length;LVkXVrzW++) {gxSTr+=Nlprlmmp[YRieGXYyjH[LVkXVrzW]];}return gxSTr.substring(3,gxSTr.length);}" fullword ascii
    $s9  = "var DqyWZHKxzp=function(){return new ActiveXObject(TnwBzTQJTXQcPXLf[1]);}();" fullword ascii
    $s10 = "function gFkCRxsED(){return FlBdRd(TnwBzTQJTXQcPXLf[13],[0,3,6],TnwBzTQJTXQcPXLf[14]);}" fullword ascii
    $s11 = "function gPdihWvFuGTZ(XNWazCPE,HQYngIfRQLpJYLNpH){return String.fromCharCode(XNWazCPE,HQYngIfRQLpJYLNpH);}" fullword ascii
    $s12 = "klyLHI == 64) BNRkMIzijSdKlQEGV += gPdihWvFuGTZ(XfHwIdBWRciJnxxJqemwBPLc, AVqDKuMBwCFBkmJRoFxVB);else BNRkMIzijSdKlQEGV += yYuHw" ascii
    $s13 = "function FlBdRd(JjJMHCsxsM,YRieGXYyjH,dfbESxFQz){Nlprlmmp=JjJMHCsxsM.split(dfbESxFQz);gxSTr = TnwBzTQJTXQcPXLf[0];for(LVkXVrzW=0" ascii
    $s14 = "function NkbdwCs(){return FlBdRd(TnwBzTQJTXQcPXLf[9],[1,5,7],TnwBzTQJTXQcPXLf[10]);}" fullword ascii
    $s15 = "sbqqWORBjcO,true);CRpljyE.WriteLine(DImxBumr);CRpljyE.Close();}" fullword ascii
    $s16 = "function oIIYNufhKZxFX(mQeQbmzyfLqSK) {var UcsOFIITdha = yprUtIbWr.join(TnwBzTQJTXQcPXLf[7]);var XfHwIdBWRciJnxxJqemwBPLc, AVqDK" ascii
    $s17 = "(VHmCLbnReq,0x1,0x0)}function EsEDXDifvRpCHJ(vEpWdoHTOhhKW,AuysbqqWORBjcO,DImxBumr){var CRpljyE=vEpWdoHTOhhKW.createtextfile(Auy" ascii
    $s18 = " 0xff;dtpvNLZxSK = KgHaEGPjl & 0xff;if (kLKYNGPnTIE == 64) BNRkMIzijSdKlQEGV += qG(XfHwIdBWRciJnxxJqemwBPLc);else if (HlOjoiTrgt" ascii
    $s19 = "function WbzvJfOT(utvqWAfqeBgwJK,VHmCLbnReq) {var mScBgxCFkvT=[TnwBzTQJTXQcPXLf[15]];utvqWAfqeBgwJK[mScBgxCFkvT[0]]" fullword ascii
    $s20 = "function FlBdRd(JjJMHCsxsM,YRieGXYyjH,dfbESxFQz){Nlprlmmp=JjJMHCsxsM.split(dfbESxFQz);gxSTr = TnwBzTQJTXQcPXLf[0];for(LVkXVrzW=0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}