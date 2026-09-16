rule sig_20160314_2d635577ba5551ac42c531e54f98e3c2 {
  meta:
    description = "datamaliciousorder - file 20160314_2d635577ba5551ac42c531e54f98e3c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69c115557ce4ac1ae744930af75eaa9ad77e86258e311b262b46dc9c1f40378d"

  strings:
    $s1  = "return UwpiYIK[0] + UwpiYIK[2] + UwpiYIK[4] + \".F\" + UwpiYIK[7] + UwpiYIK[9] + UwpiYIK[12] + UwpiYIK[14];" fullword ascii
    $s2  = "var PZ = true  , mXWJ = diR[7] + diR[9] + diR[11];" fullword ascii
    $s3  = "txwgY.open(VQUyz,AoBHQ,false);" fullword ascii
    $s4  = "var UwpiYIK = \"Sc fzCcVKw r ugwnAeoKr ipting IDLUMTr gEe ile npUuDdQvLkGjAy System ze HvYwP Obj KEPlvr ect PRAjBWz FgIrr\".spli" ascii
    $s5  = "var UwpiYIK = \"Sc fzCcVKw r ugwnAeoKr ipting IDLUMTr gEe ile npUuDdQvLkGjAy System ze HvYwP Obj KEPlvr ect PRAjBWz FgIrr\".spli" ascii
    $s6  = "var diR = (\"2.XMLHTTP ZlpYmiW LAMzz XML ream St JqKBiWWy AD HrmYOUT O Lehu D\").split(\" \");" fullword ascii
    $s7  = "return takCn.status;" fullword ascii
    $s8  = "function sKUe(Fopii) {" fullword ascii
    $s9  = "if(Y>=s.length) {break;}" fullword ascii
    $s10 = "return EbIMD;" fullword ascii
    $s11 = "return TIXbHKc" fullword ascii
    $s12 = "function rnom(ObRVv,PlYPV) {" fullword ascii
    $s13 = "return oUJSELV(Rl,bAGPx[855-849]+bAGPx[757-750]+bAGPx[398-390]);" fullword ascii
    $s14 = "function oUJSELV(AzNB,wOPzo) {" fullword ascii
    $s15 = "return AzNB.ExpandEnvironmentStrings(wOPzo);" fullword ascii
    $s16 = "return Fuwgmb.position=836-836;" fullword ascii
    $s17 = "return Poz.size;" fullword ascii
    $s18 = "if (tZFld > 161554-827){return true;} else {return false;}" fullword ascii
    $s19 = "function azNPKPKUH(MTEDzbXtcGo) {" fullword ascii
    $s20 = "function VYiad(NQJgvh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}