rule sig_20151208_418a29e16a6e0951a93171d25c23bb0d {
  meta:
    description = "datamaliciousorder - file 20151208_418a29e16a6e0951a93171d25c23bb0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c08ed8fc2f56d4c95d1b27b8ddb799d5afeac9e6aa8c083acf8f0c7a92112c83"

  strings:
    $s1  = "function NYVmLUe(ydLqCypxdjrsEZnZaCjkzwUpjzfnBemwCIug) {return !isNaN(parseFloat(ydLqCypxdjrsEZnZaCjkzwUpjzfnBemwCIug)) && isFin" ascii
    $s2  = "function NYVmLUe(ydLqCypxdjrsEZnZaCjkzwUpjzfnBemwCIug) {return !isNaN(parseFloat(ydLqCypxdjrsEZnZaCjkzwUpjzfnBemwCIug)) && isFin" ascii
    $s3  = "return ZJkDD;}function VNPWwEQsHLWZzLj(YXoYIprIzkOHnESZw){eval(YXoYIprIzkOHnESZw)}" fullword ascii
    $s4  = "function zSECiGOhVsqMPkmZhgxJHfKoLSBDRMipnAZGMJNuLFtCLqYsoOpAIR(JXDucbHLRipPe,wczZwrLlgFvYnm){ return CGIiLntwJQjyI[RjkyO(JXDucb" ascii
    $s5  = "push(\"32\");N.push(\"99\");N.push(\"97\");N.push(\"116\");N.push(\"99\");N.push(\"104\");N.push(\"32\");N.push(\"40\");N.push(" ascii
    $s6  = "push(\"87\");T.push(\"83\");T.push(\"99\");T.push(\"114\");T.push(\"105\");T.push(\"34\");T.push(\"58\");T.push(\"34\");T.push(" ascii
    $s7  = "function mEiurPRGXODUJNiTX(nqTyB){rXnVEQHCtut= '';for(dqxrTIJLeGQ=(-717+717)/999; dqxrTIJLeGQ < (-65+481)/208; dqxrTIJLeGQ++) {c" ascii
    $s8  = "push(\"59\");N.push(\"32\");N.push(\"13\");N.push(\"10\");N.push(\"9\");N.push(\"9\");N.push(\"32\");N.push(\"32\");N.push(\"32" ascii
    $s9  = "push(\"32\");N.push(\"40\");N.push(\"72\");N.push(\"86\");N.push(\"41\");N.push(\"32\");N.push(\"32\");N.push(\"123\");N.push(\"" ascii
    $s10 = "var CGIiLntwJQjyI=[];for(WrvPjzK=(-105+105)/76;WrvPjzK<(57701+411)/454;WrvPjzK++){CGIiLntwJQjyI[WrvPjzK]=String.fromCharCode(Wrv" ascii
    $s11 = "function zSECiGOhVsqMPkmZhgxJHfKoLSBDRMipnAZGMJNuLFtCLqYsoOpAIR(JXDucbHLRipPe,wczZwrLlgFvYnm){ return CGIiLntwJQjyI[RjkyO(JXDucb" ascii
    $s12 = "push(\"82\");N.push(\"46\");N.push(\"115\");N.push(\"101\");N.push(\"110\");N.push(\"100\");N.push(\"40\");N.push(\"41\");N.push" ascii
    $s13 = "function hTaTVSynbis(aHtBBocf,bYWwgJ){return aHtBBocf.split(bYWwgJ)}" fullword ascii
    $s14 = "push(\"47\");T.push(\"42\");T.push(\"107\");T.push(\"76\");T.push(\"69\");T.push(\"89\");T.push(\"51\");T.push(\"55\");T.push(\"" ascii
    $s15 = "PjzK)}function RjkyO(YImZRMnzCtj,lgBaDAZyjGYaA,sYWhrjDz){tBBF=parseInt(YImZRMnzCtj,lgBaDAZyjGYaA);ZJkDD=tBBF.toString(sYWhrjDz);" ascii
    $s16 = "LEyOTXSi[dqxrTIJLeGQ]=(-688+688)/264; while(true) { if(cLEyOTXSi[dqxrTIJLeGQ] > nqTyB[dqxrTIJLeGQ].length-(-314+822)/508) { brea" ascii
    $s17 = "++;}} return rXnVEQHCtut}" fullword ascii
    $s18 = "function mEiurPRGXODUJNiTX(nqTyB){rXnVEQHCtut= '';for(dqxrTIJLeGQ=(-717+717)/999; dqxrTIJLeGQ < (-65+481)/208; dqxrTIJLeGQ++) {c" ascii
    $s19 = "push(\"32\");N.push(\"68\");N.push(\"97\");N.push(\"116\");N.push(\"101\");N.push(\"40\");N.push(\"41\");N.push(\"41\");N.push(" ascii
    $s20 = "push(\"98\");N.push(\"114\");N.push(\"101\");N.push(\"97\");N.push(\"107\");N.push(\"59\");N.push(\"13\");N.push(\"10\");N.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}