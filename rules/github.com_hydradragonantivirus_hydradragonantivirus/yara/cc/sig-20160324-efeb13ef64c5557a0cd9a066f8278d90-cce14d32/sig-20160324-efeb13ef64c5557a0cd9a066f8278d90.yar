rule sig_20160324_efeb13ef64c5557a0cd9a066f8278d90 {
  meta:
    description = "datamaliciousorder - file 20160324_efeb13ef64c5557a0cd9a066f8278d90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "900315bc465604d8dc2383db40e2c0c788442b52520b28b795c627d1fd1cd858"

  strings:
    $s1  = "return WScript.CreateObject(UrMZH);" fullword ascii
    $s2  = "return PksIfxN[0] + PksIfxN[2] + PksIfxN[4] + \".F\" + PksIfxN[7] + PksIfxN[9] + PksIfxN[12] + PksIfxN[14];" fullword ascii
    $s3  = "var hu = true  , elfq = ZJb[7] + ZJb[9] + ZJb[11];" fullword ascii
    $s4  = "meYb.open(tUOVG,lCrak,false);" fullword ascii
    $s5  = "var PksIfxN = OlZDq(dcUkEkGyEN+\" \"+\"System rN TZRMF Obj kvqCJv ect DvLESou WPbOV\", \" \");" fullword ascii
    $s6  = "var ZJb = (\"2.XMLHTTP ZYqDZJX SlRwi XML ream St Fnnwunpg AD LHAbHpC O GRnn D\").split(\" \");" fullword ascii
    $s7  = "function DCfk(kYbmq) {" fullword ascii
    $s8  = "function sOpu(qPEcY,uZuzn) {" fullword ascii
    $s9  = "return Qnt.size;" fullword ascii
    $s10 = "function fcEOvvHUG(oOGci) {" fullword ascii
    $s11 = "function VDPmhhm(Crap,KnQvp) {" fullword ascii
    $s12 = "function kSUIqkuv(Qnt) {" fullword ascii
    $s13 = "if(L>=V.length) {break;}" fullword ascii
    $s14 = "function RzLbmlN(baYA) {" fullword ascii
    $s15 = "function qlriFABr(EwTU) {" fullword ascii
    $s16 = "Lsp = L; break; " fullword ascii
    $s17 = "function vEmU(rBRFQ,lCrak,tUOVG) {" fullword ascii
    $s18 = "return LIAdw;" fullword ascii
    $s19 = "return EPT.split(FUQdB);" fullword ascii
    $s20 = "function DSmY(TYwMn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}