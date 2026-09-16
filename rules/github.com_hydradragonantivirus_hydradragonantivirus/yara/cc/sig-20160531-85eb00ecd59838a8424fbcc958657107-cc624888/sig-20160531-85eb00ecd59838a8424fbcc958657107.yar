rule sig_20160531_85eb00ecd59838a8424fbcc958657107 {
  meta:
    description = "datamaliciousorder - file 20160531_85eb00ecd59838a8424fbcc958657107.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a8daf4a445bb3cd20bbe5ca420d84870abeb0fc95d25140bad4bcf74a81b49a"

  strings:
    $s1  = "var hQNVLrW=function(){return WScript.CreateObject(RwKFlxMXmncxgSVArWF[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ZpUqIaVyCiYVrMtLHOcLJzUw(mgzVY,hLDfzxVrhwWfWvdkorpSOeH){return mgzVY.charAt(hLDfzxVrhwWfWvdkorpSOeH);}" fullword ascii
    $s3  = "function DzpLrQQQfveSINCoiOomTV(CTXiLUZYPINcse,FTwCod){return String.fromCharCode(CTXiLUZYPINcse,FTwCod);}" fullword ascii
    $s4  = "function pIInQZVwFz(dmqPo,PQGQyOmprYmHp){return dmqPo.indexOf(PQGQyOmprYmHp);}" fullword ascii
    $s5  = "RaICYT,true);ZTFVWOJkLVsWme.WriteLine(AnMnbA);ZTFVWOJkLVsWme.Close();}" fullword ascii
    $s6  = "function oSeAfYdgiqfr(spviDCvgzOIjshDtBOTdEO,IXtILSHFYpAqeekBFp,gHDfYBHToMj){return String.fromCharCode(spviDCvgzOIjshDtBOTdEO,I" ascii
    $s7  = "var GaRjzOktpjPS=function(){return new ActiveXObject(RwKFlxMXmncxgSVArWF[1]);}();" fullword ascii
    $s8  = "function btjRTiA(){return fTfTRbf(RwKFlxMXmncxgSVArWF[13],[0,3,6],RwKFlxMXmncxgSVArWF[14]);}" fullword ascii
    $s9  = "function MH(fxZunwFCVF){return String.fromCharCode(fxZunwFCVF);}" fullword ascii
    $s10 = "function fTfTRbf(BCHGiTfoZ,zPSXHruafH,haqHl){kitaeyo=BCHGiTfoZ.split(haqHl);KaaldjfjLCSpm = RwKFlxMXmncxgSVArWF[0];for(kAcHWxzvo" ascii
    $s11 = "WJ=0;kAcHWxzvoWJ<zPSXHruafH.length;kAcHWxzvoWJ++) {KaaldjfjLCSpm+=kitaeyo[zPSXHruafH[kAcHWxzvoWJ]];}return KaaldjfjLCSpm.substri" ascii
    $s12 = "iqfr(HltIURzntANEjdw, qPjzCYrcJAQElLWJMZe, tjPLcdHFssZQZRlqvKA);} while (qqrqweeG < IhQDooNKZUoHo.length);return ATiPiRBhtynzj;}" ascii
    $s13 = "function KxMfutYRET(IhQDooNKZUoHo) {var tEJaOsRVaGprwxwDQa = IlZrTdeRLFCjIPQ.join(RwKFlxMXmncxgSVArWF[7]);var HltIURzntANEjdw, q" ascii
    $s14 = "function bHOSbWioaYxQ(ClCirSWPSCZc,bLTnTtU) {var ieOkbkfbkUgnC=[RwKFlxMXmncxgSVArWF[15]];ClCirSWPSCZc[ieOkbkfbkUgnC[0]]" fullword ascii
    $s15 = "function ECgjnRrWeD(){return hQNVLrW.ExpandEnvironmentStrings(fEHrhYymJzl())}" fullword ascii
    $s16 = "function oSeAfYdgiqfr(spviDCvgzOIjshDtBOTdEO,IXtILSHFYpAqeekBFp,gHDfYBHToMj){return String.fromCharCode(spviDCvgzOIjshDtBOTdEO,I" ascii
    $s17 = "(bLTnTtU,0x1,0x0)}function PyqpVyQ(itRiowabjrqjH,nViMZtDjRaICYT,AnMnbA){var ZTFVWOJkLVsWme=itRiowabjrqjH.createtextfile(nViMZtDj" ascii
    $s18 = "function fEHrhYymJzl(){return fTfTRbf(RwKFlxMXmncxgSVArWF[9],[1,5,7],RwKFlxMXmncxgSVArWF[10]);}" fullword ascii
    $s19 = "function fTfTRbf(BCHGiTfoZ,zPSXHruafH,haqHl){kitaeyo=BCHGiTfoZ.split(haqHl);KaaldjfjLCSpm = RwKFlxMXmncxgSVArWF[0];for(kAcHWxzvo" ascii
    $s20 = "tjPLcdHFssZQZRlqvKA = kUQYgAeDHPahIssbJVDMlC & 0xff;if (aXwqnMQM == 64) ATiPiRBhtynzj += MH(HltIURzntANEjdw);else if (xODZqnbLPH" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}