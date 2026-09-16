rule sig_20160323_5d821a609066211e56d50845e304ba50 {
  meta:
    description = "datamaliciousorder - file 20160323_5d821a609066211e56d50845e304ba50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4aad31a882e5aa171b68167373af47768582a888bb3f6fa6963d84ad8af2c7"

  strings:
    $s1  = "return WScript.CreateObject(NjwVY);" fullword ascii
    $s2  = "return DXKDUaq[0] + DXKDUaq[2] + DXKDUaq[4] + \".F\" + DXKDUaq[7] + DXKDUaq[9] + DXKDUaq[12] + DXKDUaq[14];" fullword ascii
    $s3  = "var Sw = true  , NfPM = UeR[7] + UeR[9] + UeR[11];" fullword ascii
    $s4  = "CFuS.open(BweRo,zpGWZ,false);" fullword ascii
    $s5  = "var UeR = (\"2.XMLHTTP RjEeWNP COYWr XML ream St pqOUsWQs AD pauMxPB O bhml D\").split(\" \");" fullword ascii
    $s6  = "var DXKDUaq = daKFc(gZBgjHgWWV+\" \"+\"System pH chKNm Obj IbeFOb ect QJmgkNA xZLXo\", \" \");" fullword ascii
    $s7  = "return fKpnSRB(Lw,yuslb[972-966]+yuslb[608-601]+yuslb[764-756]);" fullword ascii
    $s8  = "function qPby(HmKph) {" fullword ascii
    $s9  = "function ylFi(kUVjj,WwfLq) {" fullword ascii
    $s10 = "function TubQ(iSucE) {" fullword ascii
    $s11 = "function JlALV(iLevZG) {" fullword ascii
    $s12 = "function HXIFP(dNTqbd) {" fullword ascii
    $s13 = "if (mpkgy > 191100-960){return true;} else {return false;}" fullword ascii
    $s14 = "return JvqB[PSkSAg[0]];" fullword ascii
    $s15 = "return DeN.split(TnpfT);" fullword ascii
    $s16 = "return dNTqbd/*Kg0vfvRIwVWJ2Ft8XUrMdQ2Fn*/.position=211-211;" fullword ascii
    $s17 = "function FTqK(mrirs,zpGWZ,BweRo) {" fullword ascii
    $s18 = "return new ActiveXObject(lRze);" fullword ascii
    $s19 = "function Oruj(bTRfr) {" fullword ascii
    $s20 = "return AxBKU.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}