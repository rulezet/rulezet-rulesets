rule sig_20151210_ab544c568453c6a4adcf1264e4d602bd {
  meta:
    description = "datamaliciousorder - file 20151210_ab544c568453c6a4adcf1264e4d602bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0c2c52e6bcaa48fcf673991cfb98c7d91684482707c574d27f8604f274a51f"

  strings:
    $s1  = "function SnsYeLi(drcQhpZZhtGCxwVBhdfrHUBFccbpcLqbIcQP) {return !isNaN(parseFloat(drcQhpZZhtGCxwVBhdfrHUBFccbpcLqbIcQP)) && isFin" ascii
    $s2  = "function SnsYeLi(drcQhpZZhtGCxwVBhdfrHUBFccbpcLqbIcQP) {return !isNaN(parseFloat(drcQhpZZhtGCxwVBhdfrHUBFccbpcLqbIcQP)) && isFin" ascii
    $s3  = "}} return GmnbjAXCFsc}" fullword ascii
    $s4  = "function JYzjDyasmCszkCiCG(rVkqD){GmnbjAXCFsc= '';for(JlusepHOFUJ=(-945+945)/848; JlusepHOFUJ < (-3+839)/418; JlusepHOFUJ++) {xn" ascii
    $s5  = "function SkYUQasuTSObjlpEHsBMBMOAQTGvfbpLUwvJLhzliLyGaDZqdrTwzk(pyWwRbhhVQmnv,PeqgyTQzqNkacl){ return KwHna[aYvZP(pyWwRbhhVQmnv[" ascii
    $s6  = "function JYzjDyasmCszkCiCG(rVkqD){GmnbjAXCFsc= '';for(JlusepHOFUJ=(-945+945)/848; JlusepHOFUJ < (-3+839)/418; JlusepHOFUJ++) {xn" ascii
    $s7  = " nakIj;}function zlphjEmCyaSjPqz(CReSSkNiQkvFUVSVy){eval(CReSSkNiQkvFUVSVy)}" fullword ascii
    $s8  = "function pjaLgQNSBgQ(MWvkqAVq,icRCfn){return MWvkqAVq.split(icRCfn)}" fullword ascii
    $s9  = "PyqHHgn[JlusepHOFUJ]=(-729+729)/543; while(true) { if(xnPyqHHgn[JlusepHOFUJ] > rVkqD[JlusepHOFUJ].length-(-34+515)/481) { break;" ascii
    $s10 = "function SkYUQasuTSObjlpEHsBMBMOAQTGvfbpLUwvJLhzliLyGaDZqdrTwzk(pyWwRbhhVQmnv,PeqgyTQzqNkacl){ return KwHna[aYvZP(pyWwRbhhVQmnv[" ascii
    $s11 = "function aYvZP(zqeHwFqUcah,LLMvRVsrFZtoO,LrwwZufh){jVvE=parseInt(zqeHwFqUcah,LLMvRVsrFZtoO);nakIj=jVvE.toString(LrwwZufh);return" ascii
    $s12 = "function aYvZP(zqeHwFqUcah,LLMvRVsrFZtoO,LrwwZufh){jVvE=parseInt(zqeHwFqUcah,LLMvRVsrFZtoO);nakIj=jVvE.toString(LrwwZufh);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}