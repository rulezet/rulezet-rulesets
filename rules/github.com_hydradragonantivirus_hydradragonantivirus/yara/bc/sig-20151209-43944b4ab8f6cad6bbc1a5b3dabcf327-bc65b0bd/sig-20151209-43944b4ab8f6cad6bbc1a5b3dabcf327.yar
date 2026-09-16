rule sig_20151209_43944b4ab8f6cad6bbc1a5b3dabcf327 {
  meta:
    description = "datamaliciousorder - file 20151209_43944b4ab8f6cad6bbc1a5b3dabcf327.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f6553154aec67a3e079775e739975c4b877d8a1b0a9dd2c7113ea915ee9ee8"

  strings:
    $s1  = "function DtxpXDh(wfLuJqhRhIDtgoxmghxHddnwxUXgqIgsjNtR) {return !isNaN(parseFloat(wfLuJqhRhIDtgoxmghxHddnwxUXgqIgsjNtR)) && isFin" ascii
    $s2  = "function DtxpXDh(wfLuJqhRhIDtgoxmghxHddnwxUXgqIgsjNtR) {return !isNaN(parseFloat(wfLuJqhRhIDtgoxmghxHddnwxUXgqIgsjNtR)) && isFin" ascii
    $s3  = "} return syLRfuKADAx}" fullword ascii
    $s4  = "function pUNNczXZqEg(enHGgtKG,csCmtv){return enHGgtKG.split(csCmtv)}" fullword ascii
    $s5  = "function RdHMMGDuPQGYBWRPGwQRmNKtNonmiSsEWDAZIWfPDORUttMnPGlXLv(ddtwiyCryQirE,AjNXGOHPZsPQae){ return mAEwg[MYGUo(ddtwiyCryQirE[" ascii
    $s6  = "function MYGUo(SbjUPbuFxqf,ZHXECjjaymjbf,KvkMZzpC){gKOC=parseInt(SbjUPbuFxqf,ZHXECjjaymjbf);hpqXs=gKOC.toString(KvkMZzpC);return" ascii
    $s7  = " hpqXs;}function rruoBwYCVHJEyYk(IPXLZvNVODXrQSxCR){eval(IPXLZvNVODXrQSxCR)}" fullword ascii
    $s8  = "bGbPv[hZKKNHxnnxg]=(-465+465)/825; while(true) { if(ESlgbGbPv[hZKKNHxnnxg] > oMbRk[hZKKNHxnnxg].length-(-107+588)/481) { break; " ascii
    $s9  = "function MYGUo(SbjUPbuFxqf,ZHXECjjaymjbf,KvkMZzpC){gKOC=parseInt(SbjUPbuFxqf,ZHXECjjaymjbf);hpqXs=gKOC.toString(KvkMZzpC);return" ascii
    $s10 = "function RdHMMGDuPQGYBWRPGwQRmNKtNonmiSsEWDAZIWfPDORUttMnPGlXLv(ddtwiyCryQirE,AjNXGOHPZsPQae){ return mAEwg[MYGUo(ddtwiyCryQirE[" ascii
    $s11 = "function LCaaYPnzjjNkvIejd(oMbRk){syLRfuKADAx= '';for(hZKKNHxnnxg=(-11+11)/34; hZKKNHxnnxg < (939+981)/960; hZKKNHxnnxg++) {ESlg" ascii
    $s12 = "function LCaaYPnzjjNkvIejd(oMbRk){syLRfuKADAx= '';for(hZKKNHxnnxg=(-11+11)/34; hZKKNHxnnxg < (939+981)/960; hZKKNHxnnxg++) {ESlg" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}