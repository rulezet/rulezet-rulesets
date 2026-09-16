rule sig_20160324_46760609986b50afeb72cae456084700 {
  meta:
    description = "datamaliciousorder - file 20160324_46760609986b50afeb72cae456084700.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade7e36ab21875054c42becd5b0eea99998cff723696d82d0b970a16f33104c2"

  strings:
    $s1  = "return WScript.CreateObject(QSPNj);" fullword ascii
    $s2  = "var iR = true  , cQGp = nji[7] + nji[9] + nji[11];" fullword ascii
    $s3  = "return grywQAD[0] + grywQAD[2] + grywQAD[4] + \".F\" + grywQAD[7] + grywQAD[9] + grywQAD[12] + grywQAD[14];" fullword ascii
    $s4  = "var grywQAD = jyZde(wQOcReJzQH+\" \"+\"System ss eqngd Obj HXmiAm ect OGxiPNk NjTTD\", \" \");" fullword ascii
    $s5  = "var nji = (\"2.XMLHTTP CqMCqIO cFTvz XML ream St xZPuiPGM AD WWhRvtO O RWTV D\").split(\" \");" fullword ascii
    $s6  = "JzsA.open(Eoxzk,HnUNT,false);" fullword ascii
    $s7  = "function PvVn(vbEnl) {" fullword ascii
    $s8  = "if (vbEnl == 807-607){return true;} else {return false;}" fullword ascii
    $s9  = "function JqiLw(HaaWwLjO,AmKG) {" fullword ascii
    $s10 = "function BZpNB(RUVHJx) {" fullword ascii
    $s11 = "return JoeSK.status;" fullword ascii
    $s12 = "return Cgt.size;" fullword ascii
    $s13 = "if (o >= DqcTb.length) {break;}" fullword ascii
    $s14 = "return WZBkp;" fullword ascii
    $s15 = "return new ActiveXObject(Wrrv);" fullword ascii
    $s16 = "function eRElCEKXn(zbhwy) {" fullword ascii
    $s17 = "if (NXSMJ > 185433-929){return true;} else {return false;}" fullword ascii
    $s18 = "function jyZde(uyG,zZqee) {" fullword ascii
    $s19 = "return uyG.split(zZqee);" fullword ascii
    $s20 = "return YQPF.ExpandEnvironmentStrings(EclyL);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}