rule sig_20160323_4430185bda0e80245f21a07589e829fd {
  meta:
    description = "datamaliciousorder - file 20160323_4430185bda0e80245f21a07589e829fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "986d937de35f80309fcae5387101dd38a925e6e1b7e139816d0125093ba618d6"

  strings:
    $s1  = "return WScript.CreateObject(LkurZ);" fullword ascii
    $s2  = "var iv = true  , nWND = iem[7] + iem[9] + iem[11];" fullword ascii
    $s3  = "return uReWTvS[0] + uReWTvS[2] + uReWTvS[4] + \".F\" + uReWTvS[7] + uReWTvS[9] + uReWTvS[12] + uReWTvS[14];" fullword ascii
    $s4  = "var iem = (\"2.XMLHTTP dlsGUma KgyHf XML ream St zsiKePPH AD rwHbLoH O LAXn D\").split(\" \");" fullword ascii
    $s5  = "xnre.open(kdJCY,Hydrm,false);" fullword ascii
    $s6  = "function XGiAsniHk(eKKIbflTmPu) {" fullword ascii
    $s7  = "var KAoySTPj = tKire(\"HAsh@Ws@zQOHSfl@c@XYNRDZ@ri\"+\"@pt@WUakXqcM@.S@pvbBY@he@ATMijs@ll@CooGtdS@eGNvXVqV@yTuu\", \"@\");" fullword ascii
    $s8  = "var uReWTvS = tKire(vFipsLdJeY+\" \"+\"System fG sNmLG Obj QkWFWB ect GulOYIQ TPzlD\", \" \");" fullword ascii
    $s9  = "function bcwuuGj(llVd,jElWc) {" fullword ascii
    $s10 = "return ANjT[HnVrPT[0]];" fullword ascii
    $s11 = "function UpFZ(gddBk,Ntlws) {" fullword ascii
    $s12 = "return DzTHQ.status;" fullword ascii
    $s13 = "function ZwhZ(yONfV) {" fullword ascii
    $s14 = "if (K >= TAqCo.length) {break;}" fullword ascii
    $s15 = "function zymS(IYsRe) {" fullword ascii
    $s16 = "function mmrXseHE(Tern) {" fullword ascii
    $s17 = "return new ActiveXObject(IOOe);" fullword ascii
    $s18 = "function WXERC(BiCUMW) {" fullword ascii
    $s19 = "function VMaZhJVKp(NFLPL) {" fullword ascii
    $s20 = "function JEjy(TAqCo) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}