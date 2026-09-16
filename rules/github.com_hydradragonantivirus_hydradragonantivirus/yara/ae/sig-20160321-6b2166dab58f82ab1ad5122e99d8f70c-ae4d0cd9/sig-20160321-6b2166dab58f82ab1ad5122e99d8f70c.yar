rule sig_20160321_6b2166dab58f82ab1ad5122e99d8f70c {
  meta:
    description = "datamaliciousorder - file 20160321_6b2166dab58f82ab1ad5122e99d8f70c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e47cbc0ad1ca92a40c28217b3a2c62ea442d1352b39c1e0b7a10a773ac9b2b8d"

  strings:
    $s1  = "return WScript.CreateObject(BpTzK);" fullword ascii
    $s2  = "var qk = true  , GnQW = Sox[7] + Sox[9] + Sox[11];" fullword ascii
    $s3  = "return totpxVn[0] + totpxVn[2] + totpxVn[4] + \".F\" + totpxVn[7] + totpxVn[9] + totpxVn[12] + totpxVn[14];" fullword ascii
    $s4  = "IBnNW.open(nQoJb,zFtMW,false);" fullword ascii
    $s5  = "var totpxVn = ZsXJB(VMfEyhBvLh+\" \"+\"System Qe Ofrjr Obj sHZPVn ect FwTiUPs DJvLM\", \" \");" fullword ascii
    $s6  = "var Sox = (\"2.XMLHTTP IojXCxX toYsf XML ream St TOdhaNkc AD CFduVKz O vJAK D\").split(\" \");" fullword ascii
    $s7  = "if (qEWBH > 164140-451){return true;} else {return false;}" fullword ascii
    $s8  = "function ELuhQHlk(mAed) {" fullword ascii
    $s9  = "function gMBPW(xqoOMx) {" fullword ascii
    $s10 = "function AtEh(IBnNW,zFtMW,nQoJb) {" fullword ascii
    $s11 = "function jXXs(uNZBi) {" fullword ascii
    $s12 = "function NfpH(liDIV) {" fullword ascii
    $s13 = "return RvhxQpD(Gy,JLNMx[414-408]+JLNMx[824-817]+JLNMx[326-318]);" fullword ascii
    $s14 = "function KtytShHVE(pnDQNVjNvOR) {" fullword ascii
    $s15 = "jjW = o; break; " fullword ascii
    $s16 = "return peTe[rycUKG[0]];" fullword ascii
    $s17 = "function UuaA(EyrmI) {" fullword ascii
    $s18 = "return KGMfd;" fullword ascii
    $s19 = "function QqfM(aFxXY) {" fullword ascii
    $s20 = "function EEhY(qEWBH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}