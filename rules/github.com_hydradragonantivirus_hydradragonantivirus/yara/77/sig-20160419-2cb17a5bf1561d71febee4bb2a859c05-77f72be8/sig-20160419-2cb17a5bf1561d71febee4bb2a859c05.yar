rule sig_20160419_2cb17a5bf1561d71febee4bb2a859c05 {
  meta:
    description = "datamaliciousorder - file 20160419_2cb17a5bf1561d71febee4bb2a859c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3108a46abe8e8f1a5d2eb2565f0ac83e7a009f8c6f6e8752477e8d459280ef71"

  strings:
    $s1  = "return SiEUJhY[0] + SiEUJhY[2] + SiEUJhY[4] + \".F\" + SiEUJhY[7] + SiEUJhY[9] + SiEUJhY[12] + SiEUJhY[14];" fullword ascii
    $s2  = "var Bl = true  , aYNa = KsH[7] + KsH[9] + KsH[11];" fullword ascii
    $s3  = "var KsH = (\"2.XMLHTTP yrkMIHP ZuDZa XML ream St EouCMrbE AD rKVjvZd O eSLZ D\").split(\" \");" fullword ascii
    $s4  = "QCWk.open(fJuKQ,olrOA,false);" fullword ascii
    $s5  = "function CoCZ(ofsEf) {" fullword ascii
    $s6  = "return iYpKNk[tave[694-694]]=416-416;" fullword ascii
    $s7  = "function UKSkOBD(dwTr) {" fullword ascii
    $s8  = "function MQmE(DSrnv,yAZxI) {" fullword ascii
    $s9  = "pKb = p; break; " fullword ascii
    $s10 = "function CSrucjsh(DEWq) {" fullword ascii
    $s11 = "function NJkLscpvq(hXreo) {" fullword ascii
    $s12 = "function XqNAj(ycovLFec,hPTM) {" fullword ascii
    $s13 = "function GHKC(eYgVr) {" fullword ascii
    $s14 = "function STiKRY(tSjI,bPCwVN) {" fullword ascii
    $s15 = "function xyEalhjLH(gFdvdiMxDxJ) {" fullword ascii
    $s16 = "return \"giOpwdhomglffc\";" fullword ascii
    $s17 = "return dwTr[zBspPZZ[0]+zBspPZZ[1]];" fullword ascii
    $s18 = "return new ActiveXObject(iHPS);" fullword ascii
    $s19 = "function mDUpx(OzV,JzpUr) {" fullword ascii
    $s20 = "if (K >= wZlpF.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}