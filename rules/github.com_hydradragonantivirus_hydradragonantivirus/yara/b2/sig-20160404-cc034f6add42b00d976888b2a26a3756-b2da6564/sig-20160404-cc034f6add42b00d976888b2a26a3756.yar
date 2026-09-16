rule sig_20160404_cc034f6add42b00d976888b2a26a3756 {
  meta:
    description = "datamaliciousorder - file 20160404_cc034f6add42b00d976888b2a26a3756.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d7d2f978c39434c680a2d075858c39fde082d09d1707d7cebf1d1ac710fd55f"

  strings:
    $s1  = "var Rn = true  , VLbg = oew[7] + oew[9] + oew[11];" fullword ascii
    $s2  = "return AUpGgGk[0] + AUpGgGk[2] + AUpGgGk[4] + \".F\" + AUpGgGk[7] + AUpGgGk[9] + AUpGgGk[12] + AUpGgGk[14];" fullword ascii
    $s3  = "KSCy.open(wczNp,ShFrl,false);" fullword ascii
    $s4  = "var oew = (\"2.XMLHTTP dVtiBZe DCCSq XML ream St wUGnRcOv AD JNlpxeL O vLCu D\").split(\" \");" fullword ascii
    $s5  = "var AUpGgGk = NnqzM(wKlsdvUQWm+\" \"+\"System gH pLJqg Obj vhpNsZ ect apNPwVh sHwna\", \" \");" fullword ascii
    $s6  = "function THVb(rTjdP,wOqGl) {" fullword ascii
    $s7  = "function EdAgb(FVZTNYQu,fMMO) {" fullword ascii
    $s8  = "function zKVPRf(lFirZTS) {" fullword ascii
    $s9  = "function BZMr(IOCsJ,OYwJi) {" fullword ascii
    $s10 = "function rngeIlg(VcON,ghiVF) {" fullword ascii
    $s11 = "return hSNKhPY;" fullword ascii
    $s12 = "function aUiJ(gwAfH) {" fullword ascii
    $s13 = "return Epkd;" fullword ascii
    $s14 = "function stJk(BNSmz,ShFrl,wczNp) {" fullword ascii
    $s15 = "function rRiU(KsGDI) {" fullword ascii
    $s16 = "function ZeKyPeuA(IeC) {" fullword ascii
    $s17 = "function UiVl(MdgAg) {" fullword ascii
    $s18 = "function GXQAFXMwq(VCrxzlXogtb) {" fullword ascii
    $s19 = "return ChK.split(BqmOr);" fullword ascii
    $s20 = "return IeC.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}