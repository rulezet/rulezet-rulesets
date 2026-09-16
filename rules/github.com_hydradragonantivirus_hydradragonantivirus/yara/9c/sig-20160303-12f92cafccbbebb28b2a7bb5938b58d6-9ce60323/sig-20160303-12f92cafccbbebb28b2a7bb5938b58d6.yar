rule sig_20160303_12f92cafccbbebb28b2a7bb5938b58d6 {
  meta:
    description = "datamaliciousorder - file 20160303_12f92cafccbbebb28b2a7bb5938b58d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d68b3491ea056fc7a7999977cb7c03e33aed82d04036b4ba080022a8b1939e2"

  strings:
    $s1  = "var VaAWq = \"eZmnlW SiG pt.Shell FtdUJjC Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var aSk = (mlx + \"TTP\" + \" XdYJrkk EgEUG XML ream St QJtWfzSe AD pGuntdR OD\").split(\" \");" fullword ascii
    $s3  = "var JH = true  , LfXp = aSk[7] + \"\" + aSk[9];" fullword ascii
    $s4  = "return oaoKgbU[0] + oaoKgbU[2] + oaoKgbU[4] + \".F\" + oaoKgbU[7] + oaoKgbU[9] + oaoKgbU[12] + oaoKgbU[14];" fullword ascii
    $s5  = "dpsKs.open(AXQYW,eaOKd,false);" fullword ascii
    $s6  = "var oaoKgbU = \"Sc lcIDOns r xsvMClbDa ipting YszpAFS Voh ile QjBYBLAsLUZlBA System wQ HveDN Obj mmCDNU ect qTlnSFe\".split(\" " ascii
    $s7  = "return jgXcKpq" fullword ascii
    $s8  = "return new ActiveXObject(dGWAAe);" fullword ascii
    $s9  = "if (uZshq > 159555-887){return true;} else {return false;}" fullword ascii
    $s10 = "return lUlbm.status;" fullword ascii
    $s11 = "function fBKb(oMLuT) {" fullword ascii
    $s12 = "function aNBz(ocEgm) {" fullword ascii
    $s13 = "return iEPTy;" fullword ascii
    $s14 = "return yrik.responseBody;" fullword ascii
    $s15 = "function IfwJgab(ssHV) {" fullword ascii
    $s16 = "function PPZZhfZo() {" fullword ascii
    $s17 = "function pqlzpEt(yrik) {" fullword ascii
    $s18 = "function uNnK(eLPhP) {" fullword ascii
    $s19 = "function XPXm(vHvMA,HZOnP) {" fullword ascii
    $s20 = "function GKgT(dpsKs,eaOKd,AXQYW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}