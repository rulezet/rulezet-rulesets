rule sig_20160313_e6d9f840fe54cf731cb2ca48bd85679f {
  meta:
    description = "datamaliciousorder - file 20160313_e6d9f840fe54cf731cb2ca48bd85679f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe38a6ef475ab579d33c819723bdf1f77c505dde7b1e46561689051410f8dc02"

  strings:
    $s1  = "return MRLGEsK[0] + MRLGEsK[2] + MRLGEsK[4] + \".F\" + MRLGEsK[7] + MRLGEsK[9] + MRLGEsK[12] + MRLGEsK[14];" fullword ascii
    $s2  = "var ve = true  , JImZ = XeG[7] + XeG[9] + XeG[11];" fullword ascii
    $s3  = "var XeG = (\"2.XMLHTTP drGgbuP CBMoJ XML ream St pcCQYgYv AD YSsFGFL O eafL D\").split(\" \");" fullword ascii
    $s4  = "var MRLGEsK = \"Sc fFosttr r HBCLijWBb ipting FuCQonc RSF ile jDhuADzsXGwqfP System Is PeqgA Obj fIMBYo ect IElAcPx\".split(\" " ascii
    $s5  = "ARmsc.open(eVuZL,tQPKH,false);" fullword ascii
    $s6  = "if(t>=h.length) {break;}" fullword ascii
    $s7  = "return OVtIyw.position=197-197;" fullword ascii
    $s8  = "function aiwC(ELfCX) {" fullword ascii
    $s9  = "function yrirN(vemFSX) {" fullword ascii
    $s10 = "function TxSa(vkGav) {" fullword ascii
    $s11 = "function XpFwQqRA(nUx) {" fullword ascii
    $s12 = "function zVOh(LYPOt) {" fullword ascii
    $s13 = "if (G >= ELfCX.length) {break;}" fullword ascii
    $s14 = "return dAQK.ExpandEnvironmentStrings(iihIo);" fullword ascii
    $s15 = "function uhDa(Gjsxi) {" fullword ascii
    $s16 = "if (vkGav == 727-527){return true;} else {return false;}" fullword ascii
    $s17 = "function IcqmR(OVtIyw) {" fullword ascii
    $s18 = "return bFwO.responseBody;" fullword ascii
    $s19 = "return RZvOzsh(Pj,VJgQC[117-111]+VJgQC[675-668]+VJgQC[842-834]);" fullword ascii
    $s20 = "function GBXQ(zezZT) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}