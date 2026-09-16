rule sig_20160310_4fce7f8bdf77c5fb197323b4af23a5fa {
  meta:
    description = "datamaliciousorder - file 20160310_4fce7f8bdf77c5fb197323b4af23a5fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4c9632fc93fe4302522a231b0e5eea9d7a51eaf28b9eb15f4daa2d048f08f22"

  strings:
    $s1  = "var JL = true  , oBNo = nxR[7] + nxR[9] + nxR[11];" fullword ascii
    $s2  = "return ADAnXlp[0] + ADAnXlp[2] + ADAnXlp[4] + \".F\" + ADAnXlp[7] + ADAnXlp[9] + ADAnXlp[12] + ADAnXlp[14];" fullword ascii
    $s3  = "var ADAnXlp = \"Sc GgsJtrE r ASvKpAcjx ipting jeEvIne eeX ile IMfUIaYQFUHJZn System JI UwlLe Obj MVGyqV ect mOvbsUi\".split(\" " ascii
    $s4  = "kUEYu.open(AaAft,iiEkA,false);" fullword ascii
    $s5  = "var nxR = (\"2.XMLHTTP UuTnRcK VhfSv XML ream St ReLnSnJy AD wOknsYL O ECLZ D\").split(\" \");" fullword ascii
    $s6  = "function JoLyD(wiYjnn) {" fullword ascii
    $s7  = "if (AaMEp == 733-533){return true;} else {return false;}" fullword ascii
    $s8  = "return EKEOOZf" fullword ascii
    $s9  = "function IFTj(sdDDa,RcrqI) {" fullword ascii
    $s10 = "function UPVg(aThpa) {" fullword ascii
    $s11 = "return rqgXJ;" fullword ascii
    $s12 = "function QRfxaBKG(ifLgh,JVuKec) {" fullword ascii
    $s13 = "PXq = r; break; " fullword ascii
    $s14 = "function emMqe(OEetxl) {" fullword ascii
    $s15 = "function JbGVmafaf(wcyXs,OGYXH,fkUXG,MJqy) {" fullword ascii
    $s16 = "return LQUa.ExpandEnvironmentStrings(ODgvj);" fullword ascii
    $s17 = "if (x >= aThpa.length) {break;}" fullword ascii
    $s18 = "function pJmP(ZzYmW) {" fullword ascii
    $s19 = "function RIZp(HhIAw) {" fullword ascii
    $s20 = "return AEM.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}