rule sig_20151208_c080e2b3f3b50241530aa974f204c185 {
  meta:
    description = "datamaliciousorder - file 20151208_c080e2b3f3b50241530aa974f204c185.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf77079fa1a700d6e4fda068426dbd0285227568f38ca41c9c99f7d196ef5e08"

  strings:
    $s1  = "push(\"108\");O.push(\"117\");O.push(\"100\");O.push(\"101\");O.push(\"115\");O.push(\"47\");O.push(\"112\");O.push(\"111\");O.p" ascii
    $s2  = "push(\"41\");u.push(\"41\");u.push(\"32\");u.push(\"123\");u.push(\"13\");u.push(\"10\");u.push(\"9\");u.push(\"9\");u.push(\"32" ascii
    $s3  = "function YgAMlYrbCDJ(PMDIsPDD,KYyEgu){return PMDIsPDD.split(KYyEgu)}" fullword ascii
    $s4  = "push(\"32\");u.push(\"123\");u.push(\"13\");u.push(\"10\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"" ascii
    $s5  = "ZpdnW)}function WCSjR(VVpDmXNrnDR,yVnyjmqqBDOvc,TTWDCWNn){xGGa=parseInt(VVpDmXNrnDR,yVnyjmqqBDOvc);rsJTR=xGGa.toString(TTWDCWNn)" ascii
    $s6  = "push(\"95\");O.push(\"112\");O.push(\"97\");O.push(\"103\");O.push(\"101\");O.push(\"115\");O.push(\"95\");O.push(\"115\");O.pus" ascii
    $s7  = ";}} return nxlrTrBuKoK}" fullword ascii
    $s8  = "var uIOHDmPoqlloU=[];for(IfZpdnW=(-607+607)/233;IfZpdnW<(127057+47)/993;IfZpdnW++){uIOHDmPoqlloU[IfZpdnW]=String.fromCharCode(If" ascii
    $s9  = ";return rsJTR;}function mEeWzEdevBgVWUS(aVKdHHlnhTqpPiBNr){eval(aVKdHHlnhTqpPiBNr)}" fullword ascii
    $s10 = "function vwkIkBwQUErMpXEaTisuaNhDFlRUFBtySRzqiEaHoeAxmconLIZFbR(qZlsIPriOBrjv,ZMbbAtNqjdbKnD){ return uIOHDmPoqlloU[WCSjR(qZlsIP" ascii
    $s11 = "push(\"79\");O.push(\"98\");O.push(\"106\");O.push(\"101\");O.push(\"99\");O.push(\"116\");O.push(\"40\");O.push(\"34\");O.push(" ascii
    $s12 = "function vwkIkBwQUErMpXEaTisuaNhDFlRUFBtySRzqiEaHoeAxmconLIZFbR(qZlsIPriOBrjv,ZMbbAtNqjdbKnD){ return uIOHDmPoqlloU[WCSjR(qZlsIP" ascii
    $s13 = "push(\"88\");u.push(\"110\");u.push(\"79\");u.push(\"47\");u.push(\"42\");u.push(\"82\");u.push(\"69\");u.push(\"98\");u.push(\"" ascii
    $s14 = "push(\"32\");O.push(\"116\");O.push(\"114\");O.push(\"117\");O.push(\"101\");O.push(\"32\");O.push(\"32\");O.push(\"44\");O.push" ascii
    $s15 = "push(\"34\");O.push(\"34\");O.push(\"41\");O.push(\"43\");O.push(\"34\");O.push(\"112\");O.push(\"116\");O.push(\"46\");O.push(" ascii
    $s16 = "function KCaNOxy(vkWHBjhMPrQAdghNRfXtevLlDwxxzcpocwKc) {return !isNaN(parseFloat(vkWHBjhMPrQAdghNRfXtevLlDwxxzcpocwKc)) && isFin" ascii
    $s17 = "function KCaNOxy(vkWHBjhMPrQAdghNRfXtevLlDwxxzcpocwKc) {return !isNaN(parseFloat(vkWHBjhMPrQAdghNRfXtevLlDwxxzcpocwKc)) && isFin" ascii
    $s18 = "function JBnAiHHkkoHiysqGK(loyTv){nxlrTrBuKoK= '';for(WmvrcajaknI=(-94+94)/476; WmvrcajaknI < (498+822)/660; WmvrcajaknI++) {Vfm" ascii
    $s19 = "otmqrQ[WmvrcajaknI]=(-790+790)/514; while(true) { if(VfmotmqrQ[WmvrcajaknI] > loyTv[WmvrcajaknI].length-(-459+868)/409) { break;" ascii
    $s20 = "function JBnAiHHkkoHiysqGK(loyTv){nxlrTrBuKoK= '';for(WmvrcajaknI=(-94+94)/476; WmvrcajaknI < (498+822)/660; WmvrcajaknI++) {Vfm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}