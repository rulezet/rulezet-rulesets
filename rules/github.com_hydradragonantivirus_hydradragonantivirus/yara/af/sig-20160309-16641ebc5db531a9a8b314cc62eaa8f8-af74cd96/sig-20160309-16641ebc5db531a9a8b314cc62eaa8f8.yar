rule sig_20160309_16641ebc5db531a9a8b314cc62eaa8f8 {
  meta:
    description = "datamaliciousorder - file 20160309_16641ebc5db531a9a8b314cc62eaa8f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34d0c3d1bb178e74c8c0b700ce65aa4dbd700f4211a609f6df003624fba6b32a"

  strings:
    $s1  = "var qN = true  , hywY = TQH[7] + TQH[9] + TQH[11];" fullword ascii
    $s2  = "return zeFOFao[0] + zeFOFao[2] + zeFOFao[4] + \".F\" + zeFOFao[7] + zeFOFao[9] + zeFOFao[12] + zeFOFao[14];" fullword ascii
    $s3  = "NLBbQ.open(cjJeW,aoZuT,false);" fullword ascii
    $s4  = "var TQH = (\"2.XMLHTTP toVZgfj cVezq XML ream St OIAlKPic AD QwMeMZl O mnRo D\").split(\" \");" fullword ascii
    $s5  = "var zeFOFao = \"Sc bhicTym r eZPYMaRMy ipting JlspqwQ qTv ile kjdHSUCwwyLRxE System pe TYMee Obj FvHYwU ect eELGUVQ\".split(\" " ascii
    $s6  = "return VnyuDVS(bu,GJltd[584-578]+GJltd[964-957]+GJltd[423-415]);" fullword ascii
    $s7  = "function VnyuDVS(OgUc,hRCxR) {" fullword ascii
    $s8  = "function JgDt(SBhTe) {" fullword ascii
    $s9  = "ttj = r; break; " fullword ascii
    $s10 = "function gFpB(bmlFg) {" fullword ascii
    $s11 = "function fJfOtWjwY(ldLGD,xSDiV,sNhrL,XbsA) {" fullword ascii
    $s12 = "return mvIbE;" fullword ascii
    $s13 = "return OgUc.ExpandEnvironmentStrings(hRCxR);" fullword ascii
    $s14 = "function cmjy(AokMO) {" fullword ascii
    $s15 = "if (AokMO > 195746-489){return true;} else {return false;}" fullword ascii
    $s16 = "function FlDy(NLBbQ,aoZuT,cjJeW) {" fullword ascii
    $s17 = "if(r>=E.length) {break;}" fullword ascii
    $s18 = "function cwJrSkHF(stvOR,YCupBu) {" fullword ascii
    $s19 = "if (N >= SiifN.length) {break;}" fullword ascii
    $s20 = "return cSpMkZn" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}