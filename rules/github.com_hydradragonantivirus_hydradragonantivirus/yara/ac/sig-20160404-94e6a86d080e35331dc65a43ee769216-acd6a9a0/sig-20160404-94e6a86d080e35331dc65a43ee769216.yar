rule sig_20160404_94e6a86d080e35331dc65a43ee769216 {
  meta:
    description = "datamaliciousorder - file 20160404_94e6a86d080e35331dc65a43ee769216.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960bb68e859933a2a6452098c86e24fa8b936b8c6373734f08b02fb86d040c08"

  strings:
    $s1  = "return RkvnBuh[0] + RkvnBuh[2] + RkvnBuh[4] + \".F\" + RkvnBuh[7] + RkvnBuh[9] + RkvnBuh[12] + RkvnBuh[14];" fullword ascii
    $s2  = "var TN = true  , iWrt = EYg[7] + EYg[9] + EYg[11];" fullword ascii
    $s3  = "var EYg = (\"2.XMLHTTP FwMHntO fWdcV XML ream St vIMpcIDU AD yRvYeUn O UUfv D\").split(\" \");" fullword ascii
    $s4  = "XVOG.open(jCZNE,BIyrp,false);" fullword ascii
    $s5  = "var RkvnBuh = rxRlz(kEQfwcuacv+\" \"+\"System yg Jixpy Obj TrINrs ect CcqFJyV gJIoD\", \" \");" fullword ascii
    $s6  = "if(N>=Q.length) {break;}" fullword ascii
    $s7  = "return Pke.size;" fullword ascii
    $s8  = "if (wICpH == 446-246){return true;} else {return false;}" fullword ascii
    $s9  = "return dQTUJlc;" fullword ascii
    $s10 = "return KMEP;" fullword ascii
    $s11 = "function eIoJ(lsfDb) {" fullword ascii
    $s12 = "return new ActiveXObject(osCb);" fullword ascii
    $s13 = "function xtlZ(FgBKR,MDFaG) {" fullword ascii
    $s14 = "PZS = N; break; " fullword ascii
    $s15 = "function DFyifZLwH(rQHXxIBVZVV) {" fullword ascii
    $s16 = "return HiZ.split(TQLWy);" fullword ascii
    $s17 = "function eQDV(gZwTh,BIyrp,jCZNE) {" fullword ascii
    $s18 = "function aXaZ(KwtHH) {" fullword ascii
    $s19 = "function ocuiDwL(AKDF) {" fullword ascii
    $s20 = "if (aHgDe > 156761-606){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}