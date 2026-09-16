rule sig_20160321_d1a6ca79ca13a77af19242e709285835 {
  meta:
    description = "datamaliciousorder - file 20160321_d1a6ca79ca13a77af19242e709285835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59f38801e29b936272ac8e345075ddb2f0e590946ec0415b30ff6f83d7558d55"

  strings:
    $s1  = "return WScript.CreateObject(isUyR);" fullword ascii
    $s2  = "return dBvsahw[0] + dBvsahw[2] + dBvsahw[4] + \".F\" + dBvsahw[7] + dBvsahw[9] + dBvsahw[12] + dBvsahw[14];" fullword ascii
    $s3  = "var Oh = true  , QtLG = iYi[7] + iYi[9] + iYi[11];" fullword ascii
    $s4  = "MhIgP.open(EpJnh,XALUR,false);" fullword ascii
    $s5  = "var dBvsahw = BfhQK(hZSqCtAmrL+\" \"+\"System el NksSf Obj cKMzBz ect bSHeagp XXtKZ\", \" \");" fullword ascii
    $s6  = "var iYi = (\"2.XMLHTTP bojkmLH OYSIZ XML ream St KffFFWeq AD LayYISB O vadQ D\").split(\" \");" fullword ascii
    $s7  = "if(m>=M.length) {break;}" fullword ascii
    $s8  = "return hDU.size;" fullword ascii
    $s9  = "return GOqiA.status;" fullword ascii
    $s10 = "function ACTX(hSFbi) {" fullword ascii
    $s11 = "function dKtG(GOqiA) {" fullword ascii
    $s12 = "return JGG.split(gzdki);" fullword ascii
    $s13 = "function DtGBdGpQ(hDU) {" fullword ascii
    $s14 = "return oCovE;" fullword ascii
    $s15 = "if (Q >= FpHtx.length) {break;}" fullword ascii
    $s16 = "function YkWC(OLFIt,UlzzW) {" fullword ascii
    $s17 = "function dWYMKSI(hruj) {" fullword ascii
    $s18 = "return ECLDBH.position=382-382;" fullword ascii
    $s19 = "function acYc(UDsTs) {" fullword ascii
    $s20 = "function GRRAd(rnlUrK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}