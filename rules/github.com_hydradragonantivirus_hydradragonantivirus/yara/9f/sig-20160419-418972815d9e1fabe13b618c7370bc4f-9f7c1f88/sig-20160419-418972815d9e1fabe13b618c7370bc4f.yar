rule sig_20160419_418972815d9e1fabe13b618c7370bc4f {
  meta:
    description = "datamaliciousorder - file 20160419_418972815d9e1fabe13b618c7370bc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b2f8de362aa6f4a2465d92a6a025a216ed1e7a78311fdebd697a07626df182"

  strings:
    $s1  = "return FRsGetP[0];" fullword ascii
    $s2  = "return itepWyX[0] + itepWyX[2] + itepWyX[4] + \".F\" + itepWyX[7] + itepWyX[9] + itepWyX[12] + itepWyX[14];" fullword ascii
    $s3  = "var pY = true  , nXim = IbU[7] + IbU[9] + IbU[11];" fullword ascii
    $s4  = "xfTf.open(sazmz,BALqu,false);" fullword ascii
    $s5  = "var IbU = (\"2.XMLHTTP uoxRtYs dFwNH XML ream St cjyJlFpm AD OCEEXUl O zFcN D\").split(\" \");" fullword ascii
    $s6  = "if(Q>=N.length) {break;}" fullword ascii
    $s7  = "function qeKRct(ABqBcOR) {" fullword ascii
    $s8  = "function EQIhkhz(ZnLs,gLeNx) {" fullword ascii
    $s9  = "return wUNi[FiwHeNG[0]+FiwHeNG[1]];" fullword ascii
    $s10 = "if (L >= HxixA.length) {break;}" fullword ascii
    $s11 = "function ScREJ(Qcm,mihbj) {" fullword ascii
    $s12 = "function UTcEkb(TTnv,jheFTA) {" fullword ascii
    $s13 = "function tDZzZcLj(dRWb) {" fullword ascii
    $s14 = "function xJLI(xtVnz) {" fullword ascii
    $s15 = "return wnR.size;" fullword ascii
    $s16 = "function ZdVD(BclRO) {" fullword ascii
    $s17 = "yJsX(egN); egN.type = 1; copE(egN,jXJyaNd(wb)); if (ZdVD(yhqheZUn(egN)))  {" fullword ascii
    $s18 = "function RNUZ(lphbI,BALqu,sazmz) {" fullword ascii
    $s19 = "if (BclRO > 176358-818){return true;} else {return false;}" fullword ascii
    $s20 = "function pglhn(WxsspZzv,HKsr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}