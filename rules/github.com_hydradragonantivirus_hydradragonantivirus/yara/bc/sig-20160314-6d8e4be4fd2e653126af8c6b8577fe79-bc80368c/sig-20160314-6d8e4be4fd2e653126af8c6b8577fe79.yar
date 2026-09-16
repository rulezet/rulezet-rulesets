rule sig_20160314_6d8e4be4fd2e653126af8c6b8577fe79 {
  meta:
    description = "datamaliciousorder - file 20160314_6d8e4be4fd2e653126af8c6b8577fe79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4e3da9b44de2df9340e95c6467623b055df17ec8929af812f8a692bfe03fd6a"

  strings:
    $s1  = "var rZmGbTC = \"Sc uEdMcqV r LMbIRRMzO ipting rYPBMfd xLM ile tjGcOmQjYIUvoG System Qe ABcmM Obj lCMzkZ ect XteKIRw aBJhx\".spli" ascii
    $s2  = "var rZmGbTC = \"Sc uEdMcqV r LMbIRRMzO ipting rYPBMfd xLM ile tjGcOmQjYIUvoG System Qe ABcmM Obj lCMzkZ ect XteKIRw aBJhx\".spli" ascii
    $s3  = "var ys = true  , kjoH = jXI[7] + jXI[9] + jXI[11];" fullword ascii
    $s4  = "return rZmGbTC[0] + rZmGbTC[2] + rZmGbTC[4] + \".F\" + rZmGbTC[7] + rZmGbTC[9] + rZmGbTC[12] + rZmGbTC[14];" fullword ascii
    $s5  = "IsIao.open(zglGz,vhvwN,false);" fullword ascii
    $s6  = "var jXI = (\"2.XMLHTTP vIITQYE SsDvZ XML ream St PGwpSbyA AD xKrHdwj O EoMt D\").split(\" \");" fullword ascii
    $s7  = "if(e>=J.length) {break;}" fullword ascii
    $s8  = "return Juon.responseBody;" fullword ascii
    $s9  = "return LAdiH;" fullword ascii
    $s10 = "function tdES(sbKPi) {" fullword ascii
    $s11 = "function OdbEhpp(Juon) {" fullword ascii
    $s12 = "mLN = e; break; " fullword ascii
    $s13 = "return zrekSNf(je,KpcLO[452-446]+KpcLO[915-908]+KpcLO[703-695]);" fullword ascii
    $s14 = "return yskSUIE" fullword ascii
    $s15 = "function RSuU(IsIao,vhvwN,zglGz) {" fullword ascii
    $s16 = "function plyOFzopE() {" fullword ascii
    $s17 = "function dasxZ(qJPKRE) {" fullword ascii
    $s18 = "function sZru(RCrAU) {" fullword ascii
    $s19 = "return lhM.size;" fullword ascii
    $s20 = "return wwdg.ExpandEnvironmentStrings(SfbKm);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}