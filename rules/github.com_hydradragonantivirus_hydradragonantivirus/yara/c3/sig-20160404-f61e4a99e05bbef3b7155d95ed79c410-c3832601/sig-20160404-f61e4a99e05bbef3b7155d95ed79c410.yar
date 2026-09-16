rule sig_20160404_f61e4a99e05bbef3b7155d95ed79c410 {
  meta:
    description = "datamaliciousorder - file 20160404_f61e4a99e05bbef3b7155d95ed79c410.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5165210885712a6f305a563a1c4fb16af78c065bd1a09c89c8376955463ef388"

  strings:
    $s1  = "var nT = true  , igse = vQz[7] + vQz[9] + vQz[11];" fullword ascii
    $s2  = "return YzeRsOc[0] + YzeRsOc[2] + YzeRsOc[4] + \".F\" + YzeRsOc[7] + YzeRsOc[9] + YzeRsOc[12] + YzeRsOc[14];" fullword ascii
    $s3  = "CItt.open(qKInu,qPBqg,false);" fullword ascii
    $s4  = "var YzeRsOc = hXJBR(EIbABLSyFc+\" \"+\"System mZ LhVgr Obj JFLoPw ect QwZMRfo ibiQC\", \" \");" fullword ascii
    $s5  = "var vQz = (\"2.XMLHTTP IvoqYUk mrShw XML ream St pvAMKKUQ AD IzRfruO O UpOY D\").split(\" \");" fullword ascii
    $s6  = "return tyNk[WeQffo[0]];" fullword ascii
    $s7  = "function OmawjPZi(wEE) {" fullword ascii
    $s8  = "function GtdIe(bkhnIaCc,ozYT) {" fullword ascii
    $s9  = "function TpOZVJL(UXDt,lZQdr) {" fullword ascii
    $s10 = "function QUeQ(PokjN,qPBqg,qKInu) {" fullword ascii
    $s11 = "return \"BxTfiMyiWnCSaX\";" fullword ascii
    $s12 = "if (xGEBK > 174996-136){return true;} else {return false;}" fullword ascii
    $s13 = "return prnhVad;" fullword ascii
    $s14 = "return fEGBd;" fullword ascii
    $s15 = "function EPhW(ELSPa) {" fullword ascii
    $s16 = "function NZvR(SrALI,Cewts) {" fullword ascii
    $s17 = "function ZBQVnX(oKZLumv) {" fullword ascii
    $s18 = "function uKntDqJ(tyNk) {" fullword ascii
    $s19 = "return QsC.split(DZVjK);" fullword ascii
    $s20 = "if (juTJk == 1097-897){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}