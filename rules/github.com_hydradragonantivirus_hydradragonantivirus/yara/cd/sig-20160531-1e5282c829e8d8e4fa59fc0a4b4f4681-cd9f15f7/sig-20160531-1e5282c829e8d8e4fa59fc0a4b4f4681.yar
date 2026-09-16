rule sig_20160531_1e5282c829e8d8e4fa59fc0a4b4f4681 {
  meta:
    description = "datamaliciousorder - file 20160531_1e5282c829e8d8e4fa59fc0a4b4f4681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d213c9b512255574da525643823c36e7a163c3086ff71a51d4ce5fb7faa83c3e"

  strings:
    $s1  = "var grUOm=function(){return WScript.CreateObject(kxpzGaglxdbLvncHtmj[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mKYUpjBQMJetZqAzRRC(SouhojcnnuqSYQFcfR,ghYnnrrFbYGnoIdL){return SouhojcnnuqSYQFcfR.charAt(ghYnnrrFbYGnoIdL);}" fullword ascii
    $s3  = "(DasVPZKrLNxd,0x1,0x0)}function ToHpEDDvpxwyk(VVTXZmxjP,ikvrYokJfaprtY,bqKtlWMdQQo){var gtzCP=VVTXZmxjP.createtextfile(ikvrYokJf" ascii
    $s4  = "function zUUAlgDzwvPPxKNyV(ndKMxcXS,OqXrxHkhrVqDSlrO){return String.fromCharCode(ndKMxcXS,OqXrxHkhrVqDSlrO);}" fullword ascii
    $s5  = "SqhAZzj=0;PkkNROSqhAZzj<RBQGKNWTwxY.length;PkkNROSqhAZzj++) {JRdqfuoFT+=fOpbVkJA[RBQGKNWTwxY[PkkNROSqhAZzj]];}return JRdqfuoFT.s" ascii
    $s6  = "(DasVPZKrLNxd,0x1,0x0)}function ToHpEDDvpxwyk(VVTXZmxjP,ikvrYokJfaprtY,bqKtlWMdQQo){var gtzCP=VVTXZmxjP.createtextfile(ikvrYokJf" ascii
    $s7  = "function EeAPouyHvCt(vYFcieljS,oonfbQQwbREAaNQ,xwRekjebkohackNqaLDV){return String.fromCharCode(vYFcieljS,oonfbQQwbREAaNQ,xwRekj" ascii
    $s8  = "Ablvx, ruzeXpacLHkGzwyJQSO);else BWEAhwXV += EeAPouyHvCt(FlfnOgZoFHJkqAblvx, ruzeXpacLHkGzwyJQSO, AilFLiSDvhvEnxQWOQqQ);} while " ascii
    $s9  = "function nwJZEokhWi(){return NHhPkMwYpnQCOq(kxpzGaglxdbLvncHtmj[11],[2,4,8,10],kxpzGaglxdbLvncHtmj[12]);}" fullword ascii
    $s10 = "var NvDCcmadWtD=function(){return new ActiveXObject(kxpzGaglxdbLvncHtmj[1]);}();" fullword ascii
    $s11 = "function uDyzN(PXtnwdGcqQLXThDIqOJPe,CdUbrnwEuiSMdHkoPbRVB){return PXtnwdGcqQLXThDIqOJPe.indexOf(CdUbrnwEuiSMdHkoPbRVB);}" fullword ascii
    $s12 = "function NHhPkMwYpnQCOq(JqGOyS,RBQGKNWTwxY,HAAykkc){fOpbVkJA=JqGOyS.split(HAAykkc);JRdqfuoFT = kxpzGaglxdbLvncHtmj[0];for(PkkNRO" ascii
    $s13 = "function MWjEkSvsswZGgG(FGYnpqbrwyvSD) {var qqiZIeoz = cwsIB.join(kxpzGaglxdbLvncHtmj[7]);var FlfnOgZoFHJkqAblvx, ruzeXpacLHkGzw" ascii
    $s14 = "function aMaIxQ(){return grUOm.ExpandEnvironmentStrings(bXuNFGmpRCJd())}" fullword ascii
    $s15 = "function NHhPkMwYpnQCOq(JqGOyS,RBQGKNWTwxY,HAAykkc){fOpbVkJA=JqGOyS.split(HAAykkc);JRdqfuoFT = kxpzGaglxdbLvncHtmj[0];for(PkkNRO" ascii
    $s16 = "function NQRGhuwPF(QjGTVueOlgoAC,DasVPZKrLNxd) {var iDgVXnsNmltDpG=[kxpzGaglxdbLvncHtmj[15]];QjGTVueOlgoAC[iDgVXnsNmltDpG[0]]" fullword ascii
    $s17 = "(hmgFdIySRMbQdujNhQQifhgL < FGYnpqbrwyvSD.length);return BWEAhwXV;}" fullword ascii
    $s18 = "function IIrYwI(){return NHhPkMwYpnQCOq(kxpzGaglxdbLvncHtmj[13],[0,3,6],kxpzGaglxdbLvncHtmj[14]);}" fullword ascii
    $s19 = "aprtY,true);gtzCP.WriteLine(bqKtlWMdQQo);gtzCP.Close();}" fullword ascii
    $s20 = "function EeAPouyHvCt(vYFcieljS,oonfbQQwbREAaNQ,xwRekjebkohackNqaLDV){return String.fromCharCode(vYFcieljS,oonfbQQwbREAaNQ,xwRekj" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}