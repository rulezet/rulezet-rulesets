rule sig_20160323_f3cf0b3a6d56ab81f1ebd2731a1d4e6a {
  meta:
    description = "datamaliciousorder - file 20160323_f3cf0b3a6d56ab81f1ebd2731a1d4e6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae0aa642a8f462c0d188b67800a84eda3c617618bf759a00332bf2a7598a77aa"

  strings:
    $s1  = "return WScript.CreateObject(tVjpR);" fullword ascii
    $s2  = "return PwuMpuo[0] + PwuMpuo[2] + PwuMpuo[4] + \".F\" + PwuMpuo[7] + PwuMpuo[9] + PwuMpuo[12] + PwuMpuo[14];" fullword ascii
    $s3  = "var Fg = true  , GNDN = KVY[7] + KVY[9] + KVY[11];" fullword ascii
    $s4  = "var PwuMpuo = uRZcg(vtznLrxRNr+\" \"+\"System Km JymBB Obj ojsycJ ect YgeGuQc XKfnf\", \" \");" fullword ascii
    $s5  = "tFNf.open(Wtwqw,bmPSl,false);" fullword ascii
    $s6  = "var KVY = (\"2.XMLHTTP lwzNsIX uaAji XML ream St dWFszGdk AD QrAOCjI O kXVO D\").split(\" \");" fullword ascii
    $s7  = "if(s>=c.length) {break;}" fullword ascii
    $s8  = "function HaPA(Bzzta) {" fullword ascii
    $s9  = "return eykPj;" fullword ascii
    $s10 = "function BnkNd(izRaci) {" fullword ascii
    $s11 = "return GGtmc.status;" fullword ascii
    $s12 = "return new ActiveXObject(ZLOO);" fullword ascii
    $s13 = "function Efpn(Javbf,tClJc) {" fullword ascii
    $s14 = "if (nXfwe > 165027-228){return true;} else {return false;}" fullword ascii
    $s15 = "function CTtYdZrlF(xUhTXezBCjb) {" fullword ascii
    $s16 = "function oRMG(VGbeM) {" fullword ascii
    $s17 = "return mTibYL/*sXH2c7v56DhJL6HqzAuCMStKJ*/.position=956-956;" fullword ascii
    $s18 = "function uRZcg(jAu,xQrQm) {" fullword ascii
    $s19 = "function NJAq(nXfwe) {" fullword ascii
    $s20 = "return cPL.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}