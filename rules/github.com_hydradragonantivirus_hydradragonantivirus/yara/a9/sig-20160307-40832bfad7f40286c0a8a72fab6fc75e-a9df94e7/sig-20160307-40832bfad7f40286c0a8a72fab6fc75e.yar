rule sig_20160307_40832bfad7f40286c0a8a72fab6fc75e {
  meta:
    description = "datamaliciousorder - file 20160307_40832bfad7f40286c0a8a72fab6fc75e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86d9cf1299f05ab397c6d88abe890769078041ba0c774447577a8407d590b0e2"

  strings:
    $s1  = "var lx = true  , fQgZ = dCp[7] + dCp[9] + dCp[11];" fullword ascii
    $s2  = "return lzWJYdS[0] + lzWJYdS[2] + lzWJYdS[4] + \".F\" + lzWJYdS[7] + lzWJYdS[9] + lzWJYdS[12] + lzWJYdS[14];" fullword ascii
    $s3  = "gGejR.open(NIPOI,EgZHk,false);" fullword ascii
    $s4  = "var lzWJYdS = \"Sc OTjqwNF r CMhzSkvCH ipting TTVhuoE Uwr ile bqgMlLpruOfEzZ System LA NrHVX Obj pzfGML ect WGQczNa\".split(\" " ascii
    $s5  = "var dCp = (\"2.XMLHTTP HCqiOdG bozhd XML ream St RcYLPqWY AD kJKVoKP O WOpW D\").split(\" \");" fullword ascii
    $s6  = "return Av.ExpandEnvironmentStrings(xtHMZ[6]+xtHMZ[7]+xtHMZ[8]);" fullword ascii
    $s7  = "if (KLQBG > 178288-551){return true;} else {return false;}" fullword ascii
    $s8  = "if (E >= FsnPR.length) {break;}" fullword ascii
    $s9  = "function cXlo(tSEcV) {" fullword ascii
    $s10 = "rjJ = G; break; " fullword ascii
    $s11 = "function yPOP(gGejR,EgZHk,NIPOI) {" fullword ascii
    $s12 = "function FZqB(KLQBG) {" fullword ascii
    $s13 = "return Vfo.size;" fullword ascii
    $s14 = "function aGiY(dweya) {" fullword ascii
    $s15 = "function XJGjpAYnS(JdNnuvxxlEf) {" fullword ascii
    $s16 = "if (dweya == 328-128){return true;} else {return false;}" fullword ascii
    $s17 = "function RbMn(WdiKO) {" fullword ascii
    $s18 = "return new ActiveXObject(ruvpTM);" fullword ascii
    $s19 = "function rMyz(btaSl,ImPWy) {" fullword ascii
    $s20 = "return KSrd.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}