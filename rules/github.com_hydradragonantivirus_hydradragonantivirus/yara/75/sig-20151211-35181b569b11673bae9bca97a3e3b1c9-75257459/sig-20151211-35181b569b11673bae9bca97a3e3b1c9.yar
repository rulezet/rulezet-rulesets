rule sig_20151211_35181b569b11673bae9bca97a3e3b1c9 {
  meta:
    description = "datamaliciousorder - file 20151211_35181b569b11673bae9bca97a3e3b1c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e35cc64f5db551020050b8f356f7f31ab0dd9f6bfd0d93edc5da4fb25636970"

  strings:
    $s1  = "function WwfLRhO(HhyAOoOABbOErgprVMmQbxzbfukjiqGFzGRD) {return !isNaN(parseFloat(HhyAOoOABbOErgprVMmQbxzbfukjiqGFzGRD)) && isFin" ascii
    $s2  = "function WwfLRhO(HhyAOoOABbOErgprVMmQbxzbfukjiqGFzGRD) {return !isNaN(parseFloat(HhyAOoOABbOErgprVMmQbxzbfukjiqGFzGRD)) && isFin" ascii
    $s3  = "var m=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"57\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function FJJPbycNpvXNafBjhSCycnrGZgcmoraSrvcJDYpkFMGdRvDSzEnsgE(pxqoVESNxefCD,pRjqflBBpeFkBL){ return qTlfQ[vUZju(pxqoVESNxefCD[" ascii
    $s5  = "function vUZju(QsLmeDevQaG,eKezexpEsTKgK,HhKnUSjH){zgQN=parseInt(QsLmeDevQaG,eKezexpEsTKgK);Nmavo=zgQN.toString(HhKnUSjH);return" ascii
    $s6  = "A]++;}ChTwlrhbcLA++;} return NHmbduqxrRg}" fullword ascii
    $s7  = "function LIgpHCVdSoBbZSdOv(tnccD){NHmbduqxrRg= '';ChTwlrhbcLA=(-157+157)/858; while(true){if(ChTwlrhbcLA >= (1311+615)/963)break" ascii
    $s8  = "var B=new Array(\"28\",\"26\",\"2f\",\"2e\",\"28\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "function FJJPbycNpvXNafBjhSCycnrGZgcmoraSrvcJDYpkFMGdRvDSzEnsgE(pxqoVESNxefCD,pRjqflBBpeFkBL){ return qTlfQ[vUZju(pxqoVESNxefCD[" ascii
    $s10 = "function oqGZcIaDxMY(xDDtLGLE,VTbrqQ){return xDDtLGLE.split(VTbrqQ)}" fullword ascii
    $s11 = "function vUZju(QsLmeDevQaG,eKezexpEsTKgK,HhKnUSjH){zgQN=parseInt(QsLmeDevQaG,eKezexpEsTKgK);Nmavo=zgQN.toString(HhKnUSjH);return" ascii
    $s12 = "var m=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"57\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s13 = "var B=new Array(\"28\",\"26\",\"2f\",\"2e\",\"28\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = " Nmavo;}function ypmzTNTIijfxnYb(iAgKrGfDbQQmKGote){eval(iAgKrGfDbQQmKGote)}" fullword ascii
    $s15 = ";uADQczNFz[ChTwlrhbcLA]=(-737+737)/281; while(true) { if(uADQczNFz[ChTwlrhbcLA] > tnccD[ChTwlrhbcLA].length-(588+159)/747) { bre" ascii
    $s16 = "function LIgpHCVdSoBbZSdOv(tnccD){NHmbduqxrRg= '';ChTwlrhbcLA=(-157+157)/858; while(true){if(ChTwlrhbcLA >= (1311+615)/963)break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}