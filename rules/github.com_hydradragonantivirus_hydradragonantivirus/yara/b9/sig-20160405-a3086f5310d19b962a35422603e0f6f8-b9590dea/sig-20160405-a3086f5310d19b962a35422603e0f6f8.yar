rule sig_20160405_a3086f5310d19b962a35422603e0f6f8 {
  meta:
    description = "datamaliciousorder - file 20160405_a3086f5310d19b962a35422603e0f6f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efac5c61074ccc6cf881bc55fdf0461563127df53225dc99d3371bf86dedda5d"

  strings:
    $s1  = "return SWUJWam[0] + SWUJWam[2] + SWUJWam[4] + \".F\" + SWUJWam[7] + SWUJWam[9] + SWUJWam[12] + SWUJWam[14];" fullword ascii
    $s2  = "var hr = true  , ccVJ = WrU[7] + WrU[9] + WrU[11];" fullword ascii
    $s3  = "var WrU = (\"2.XMLHTTP tBoFaIx nBFWa XML ream St hCzduWVT AD JKJdKur O JTRY D\").split(\" \");" fullword ascii
    $s4  = "lfzw.open(KSrwV,JObvU,false);" fullword ascii
    $s5  = "if(k>=C.length) {break;}" fullword ascii
    $s6  = "if (K >= HZZHj.length) {break;}" fullword ascii
    $s7  = "if (JpXcy == 879-679){return true;} else {return false;}" fullword ascii
    $s8  = "function VHtkSjUH(sJe) {" fullword ascii
    $s9  = "function rxPLEgC(hqAs,vJMUR) {" fullword ascii
    $s10 = "function ezskO(acopCt) {" fullword ascii
    $s11 = "return yQnV;" fullword ascii
    $s12 = "return pAndB;" fullword ascii
    $s13 = "function mafse(wlRoKO) {" fullword ascii
    $s14 = "return qCOk[qVmHNB[0]];" fullword ascii
    $s15 = "return Lgxll.status;" fullword ascii
    $s16 = "function FSot(UMiUF) {" fullword ascii
    $s17 = "function YlvVJ(yHr,EGMPH) {" fullword ascii
    $s18 = "function EWmA(XIqPo,ITmju) {" fullword ascii
    $s19 = "function lyiOiV(FjANxwV) {" fullword ascii
    $s20 = "function hQQF(JpXcy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}