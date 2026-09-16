rule sig_20151217_f82b7f93036a5ff91d90142ac6d457ae {
  meta:
    description = "datamaliciousorder - file 20151217_f82b7f93036a5ff91d90142ac6d457ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0a187f8b277fe825dae58ed89e87b97bbcea68c32c12ebe1f77924003cb1d15"

  strings:
    $s1  = "th.pow(Math.cos(870), 2) - 1)); while(true) { if(NtETyrdSP[KtGgftnGTQi] > UfWVz[KtGgftnGTQi].length-(-461+598)/137) { break; } i" ascii
    $s2  = "function NHZLnAANqzePjQDtw(UfWVz){YboTOoFCGzx= '';KtGgftnGTQi=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s3  = "pow(Math.cos(423), 2) - 1)));} NtETyrdSP[KtGgftnGTQi]++;}KtGgftnGTQi++;} return YboTOoFCGzx}" fullword ascii
    $s4  = ") - 1));while(true){if (KtGgftnGTQi >= (1353+753)/351){break;}NtETyrdSP[KtGgftnGTQi]=Math.round((Math.pow(Math.sin(870), 2) + Ma" ascii
    $s5  = "function ZToFJeo(jErWrKJYbrJBGaFjfrXMwUJnHVubbViOWrYu) {return !nmhnZeYEGck(dibgnFmbjtxxMYC(jErWrKJYbrJBGaFjfrXMwUJnHVubbViOWrYu" ascii
    $s6  = "function NHZLnAANqzePjQDtw(UfWVz){YboTOoFCGzx= '';KtGgftnGTQi=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s7  = "KrEhhWzCLxMOsJMgSFLbTtwrUWJEhbHxJAv([UfWVz[KtGgftnGTQi][NtETyrdSP[KtGgftnGTQi]]], Math.round((Math.pow(Math.sin(423), 2) + Math." ascii
    $s8  = "function ZToFJeo(jErWrKJYbrJBGaFjfrXMwUJnHVubbViOWrYu) {return !nmhnZeYEGck(dibgnFmbjtxxMYC(jErWrKJYbrJBGaFjfrXMwUJnHVubbViOWrYu" ascii
    $s9  = "function nmhnZeYEGck(WoOuBhQtMDnEyJ) {return isNaN(WoOuBhQtMDnEyJ);}" fullword ascii
    $s10 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s11 = "function NUzHM(vUEylOUBmPI,JlPWiqgLNJUGL,azqptkfB){nUHx=ZeRAvHUKMFxtjVamk(vUEylOUBmPI,JlPWiqgLNJUGL);mDmdm=nUHx.toString(azqptkf" ascii
    $s12 = "function dibgnFmbjtxxMYC(lMoCEcQRZhKefRlAaee) {return parseFloat(lMoCEcQRZhKefRlAaee);}" fullword ascii
    $s13 = "B);return mDmdm;}" fullword ascii
    $s14 = "function I(nWiVCHuLlgWUcn,wsYmutbssVmcF,pDzqHlrihKw) {nWiVCHuLlgWUcn[wsYmutbssVmcF]=pDzqHlrihKw;}" fullword ascii
    $s15 = "function NUzHM(vUEylOUBmPI,JlPWiqgLNJUGL,azqptkfB){nUHx=ZeRAvHUKMFxtjVamk(vUEylOUBmPI,JlPWiqgLNJUGL);mDmdm=nUHx.toString(azqptkf" ascii
    $s16 = "function zXotWkAonyChURC(zRbfmNOoppLEyCUun,kLSdiEUSEWYisqPlGOpMjqeRThxuqEXaKS,noFzCIEbeIaJNWquCFkoDUpeZYnUWqWCmqw){eval(zRbfmNOo" ascii
    $s17 = "function FPqjqGrvETOo(AtPrhjaMVlhlj) {return isFinite(AtPrhjaMVlhlj);}" fullword ascii
    $s18 = "function zXotWkAonyChURC(zRbfmNOoppLEyCUun,kLSdiEUSEWYisqPlGOpMjqeRThxuqEXaKS,noFzCIEbeIaJNWquCFkoDUpeZYnUWqWCmqw){eval(zRbfmNOo" ascii
    $s19 = "function SSOlEzlzMigPpQbawspKrEhhWzCLxMOsJMgSFLbTtwrUWJEhbHxJAv(ObZDejzirnFxx,TErOBIRHikUnni){ return QweExTk[rYYCwTaa[NUzHM(ObZ" ascii
    $s20 = "function ZeRAvHUKMFxtjVamk(vEDysMXPpE,tcGAuyEVso) {return parseInt(vEDysMXPpE,tcGAuyEVso);}" fullword ascii

  condition:
    uint16(0) == 0x5972 and
    8 of them
}