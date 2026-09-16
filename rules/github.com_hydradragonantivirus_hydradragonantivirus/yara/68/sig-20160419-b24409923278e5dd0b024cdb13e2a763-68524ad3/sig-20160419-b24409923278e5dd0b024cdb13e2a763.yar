rule sig_20160419_b24409923278e5dd0b024cdb13e2a763 {
  meta:
    description = "datamaliciousorder - file 20160419_b24409923278e5dd0b024cdb13e2a763.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13a26cd6a1d5c46db673c58494d985ac77c842f5d1f9f6491613277bb0ec415f"

  strings:
    $s1  = "return XjMDlrE[0] + XjMDlrE[2] + XjMDlrE[4] + \".F\" + XjMDlrE[7] + XjMDlrE[9] + XjMDlrE[12] + XjMDlrE[14];" fullword ascii
    $s2  = "var SH = true  , ChRJ = iCp[7] + iCp[9] + iCp[11];" fullword ascii
    $s3  = "var iCp = (\"2.XMLHTTP cKneiQi HWCSv XML ream St GFLhdPkG AD MKdtoiO O vVwQ D\").split(\" \");" fullword ascii
    $s4  = "function nhyv(ElKeY) {" fullword ascii
    $s5  = "TSHN.open(UYguX,tdqqz,false);" fullword ascii
    $s6  = "if (F >= ElKeY.length) {break;}" fullword ascii
    $s7  = "if(L>=P.length) {break;}" fullword ascii
    $s8  = "function qSAy(rJDnk,tdqqz,UYguX) {" fullword ascii
    $s9  = "return sSJ[noaJ[0]](ybRzi);" fullword ascii
    $s10 = "function dRLSHtvj(hlj) {" fullword ascii
    $s11 = "function DIWU(IKghf) {" fullword ascii
    $s12 = "function RraeakY(mfTX) {" fullword ascii
    $s13 = "function Nfbt(tAFDu,bnWgH) {" fullword ascii
    $s14 = "return mfTX[ivwPWkO[0]+ivwPWkO[1]];" fullword ascii
    $s15 = "function FPKlEt(BuIY,qyevcq) {" fullword ascii
    $s16 = "function GhrP(NMODz) {" fullword ascii
    $s17 = "function iUey(RAyqn) {" fullword ascii
    $s18 = "function UMyYgbG(rcNK,HXLnK) {" fullword ascii
    $s19 = "return \"vvLHlmdPQeVrxd\";" fullword ascii
    $s20 = "function KeRiV(sSJ,ybRzi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}