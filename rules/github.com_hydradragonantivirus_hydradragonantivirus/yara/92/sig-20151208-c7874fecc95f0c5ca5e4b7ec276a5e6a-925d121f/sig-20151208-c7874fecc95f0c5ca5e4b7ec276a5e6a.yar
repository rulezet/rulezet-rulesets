rule sig_20151208_c7874fecc95f0c5ca5e4b7ec276a5e6a {
  meta:
    description = "datamaliciousorder - file 20151208_c7874fecc95f0c5ca5e4b7ec276a5e6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a05058c73e7d908f2f4a8f9da338490e9239fb49047cb02ed5f63a731f45cdfe"

  strings:
    $s1  = "function kelDSpH(gzTiCmxekRYmOASSfKdsiricMYsoXeyJyLZd) {return !isNaN(parseFloat(gzTiCmxekRYmOASSfKdsiricMYsoXeyJyLZd)) && isFin" ascii
    $s2  = "push(\"112\");y.push(\"111\");y.push(\"110\");y.push(\"115\");y.push(\"101\");y.push(\"66\");y.push(\"111\");y.push(\"100\");y.p" ascii
    $s3  = "function kelDSpH(gzTiCmxekRYmOASSfKdsiricMYsoXeyJyLZd) {return !isNaN(parseFloat(gzTiCmxekRYmOASSfKdsiricMYsoXeyJyLZd)) && isFin" ascii
    $s4  = "push(\"45\");t.push(\"105\");t.push(\"110\");t.push(\"99\");t.push(\"108\");t.push(\"117\");t.push(\"100\");t.push(\"101\");t.pu" ascii
    $s5  = "function DAbuqscSgeqkygdNlpDNxgvYXCkZJiWqSqOOkpNOxclvyjwqGQeQEC(gYYrHFNJGJYEm,RBdUCJpaifxiMo){ return dEbUnLLMhiTli[awOiV(gYYrHF" ascii
    $s6  = "function aeWsroEfAmoTbohhR(wcbAb){IPgMuLhxobx= '';for(NXtQsmbxACO=(-131+131)/603; NXtQsmbxACO < (1222+438)/830; NXtQsmbxACO++) {" ascii
    $s7  = "wqDn)}function awOiV(XYAARdkAeRZ,BZkhtehTEAzWx,KniTsTKK){iYLa=parseInt(XYAARdkAeRZ,BZkhtehTEAzWx);KtsJF=iYLa.toString(KniTsTKK);" ascii
    $s8  = "push(\"32\");y.push(\"71\");y.push(\"107\");y.push(\"32\");y.push(\"61\");y.push(\"32\");y.push(\"49\");y.push(\"59\");y.push(\"" ascii
    $s9  = "push(\"49\");y.push(\"59\");y.push(\"32\");y.push(\"81\");y.push(\"107\");y.push(\"79\");y.push(\"46\");y.push(\"119\");y.push(" ascii
    $s10 = "push(\"67\");t.push(\"32\");t.push(\"43\");t.push(\"32\");t.push(\"34\");t.push(\"84\");t.push(\"84\");t.push(\"80\");t.push(\"3" ascii
    $s11 = "push(\"79\");t.push(\"87\");t.push(\"68\");t.push(\"84\");t.push(\"32\");t.push(\"61\");t.push(\"32\");t.push(\"34\");t.push(\"6" ascii
    $s12 = "push(\"110\");t.push(\"118\");t.push(\"105\");t.push(\"114\");t.push(\"111\");t.push(\"110\");t.push(\"109\");t.push(\"101\");t." ascii
    $s13 = "function aeWsroEfAmoTbohhR(wcbAb){IPgMuLhxobx= '';for(NXtQsmbxACO=(-131+131)/603; NXtQsmbxACO < (1222+438)/830; NXtQsmbxACO++) {" ascii
    $s14 = "var dEbUnLLMhiTli=[];for(mTXwqDn=(-999+999)/957;mTXwqDn<(18417+15)/144;mTXwqDn++){dEbUnLLMhiTli[mTXwqDn]=String.fromCharCode(mTX" ascii
    $s15 = "function KaCBobMzyqL(NmWfbVNp,WXhMuw){return NmWfbVNp.split(WXhMuw)}" fullword ascii
    $s16 = "push(\"111\");y.push(\"112\");y.push(\"101\");y.push(\"110\");y.push(\"40\");y.push(\"41\");y.push(\"59\");y.push(\"32\");y.push" ascii
    $s17 = "return KtsJF;}function YeuqACbIKHGEicM(WgnSIMCCqPIrqWnFV){eval(WgnSIMCCqPIrqWnFV)}" fullword ascii
    $s18 = "push(\"116\");y.push(\"101\");y.push(\"40\");y.push(\"41\");y.push(\"41\");y.push(\"62\");y.push(\"48\");y.push(\"44\");y.push(" ascii
    $s19 = "function DAbuqscSgeqkygdNlpDNxgvYXCkZJiWqSqOOkpNOxclvyjwqGQeQEC(gYYrHFNJGJYEm,RBdUCJpaifxiMo){ return dEbUnLLMhiTli[awOiV(gYYrHF" ascii
    $s20 = "UVIOJLpJq[NXtQsmbxACO]=(-387+387)/672; while(true) { if(UVIOJLpJq[NXtQsmbxACO] > wcbAb[NXtQsmbxACO].length-(38+230)/268) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}