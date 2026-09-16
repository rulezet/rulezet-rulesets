rule sig_20160308_8e2979c028475583dd8fab725f72e4cb {
  meta:
    description = "datamaliciousorder - file 20160308_8e2979c028475583dd8fab725f72e4cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7539fcaac7f0d950d97e2aa4bf578544b4095fc937d861d2d09ad4605a0ca535"

  strings:
    $s1  = "var Hb = true  , lqFR = PVo[7] + PVo[9] + PVo[11];" fullword ascii
    $s2  = "return bHVuzlJ[0] + bHVuzlJ[2] + bHVuzlJ[4] + \".F\" + bHVuzlJ[7] + bHVuzlJ[9] + bHVuzlJ[12] + bHVuzlJ[14];" fullword ascii
    $s3  = "SKpTk.open(IpmJy,eemKP,false);" fullword ascii
    $s4  = "var bHVuzlJ = \"Sc MDthzqL r VjemJwYrK ipting LGJKSEH WWi ile BmjwjNVSuFaNIH System by ZurAZ Obj NxhgCj ect WlOjhqC\".split(\" " ascii
    $s5  = "var PVo = (\"2.XMLHTTP vyrTBxy hXDDu XML ream St NQKVdwHj AD zVLxhNX O ssWE D\").split(\" \");" fullword ascii
    $s6  = "return RpRJPMY" fullword ascii
    $s7  = "function WnTK(lLDkI) {" fullword ascii
    $s8  = "if (GHQWc > 198159-942){return true;} else {return false;}" fullword ascii
    $s9  = "function DTiVqpjfH(HEVvs,VAbPn,zKLhH,AkFy) {" fullword ascii
    $s10 = "return kKJB.responseBody;" fullword ascii
    $s11 = "function FgWWGkcC(rEQ) {" fullword ascii
    $s12 = "function GXbB(TIlRs) {" fullword ascii
    $s13 = "SIr = w; break; " fullword ascii
    $s14 = "function ZHxC(HHJkm,mqokz) {" fullword ascii
    $s15 = "return new ActiveXObject(GbqBFe);" fullword ascii
    $s16 = "if (R >= TIlRs.length) {break;}" fullword ascii
    $s17 = "return xrwHH;" fullword ascii
    $s18 = "function CFrm(DWafJ) {" fullword ascii
    $s19 = "function TflU(Obyqz) {" fullword ascii
    $s20 = "function oOTxsAOv() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}