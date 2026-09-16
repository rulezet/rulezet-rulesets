rule sig_20160309_925efa9cda8c7e52e0aa37b4832e2dc5 {
  meta:
    description = "datamaliciousorder - file 20160309_925efa9cda8c7e52e0aa37b4832e2dc5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f01c1c00fa0b5febdce1535e2251ec329abad7dc178d443e07040a72e1560821"

  strings:
    $s1  = "var AK = true  , DJqD = XXg[7] + XXg[9] + XXg[11];" fullword ascii
    $s2  = "return BXmcXLk[0] + BXmcXLk[2] + BXmcXLk[4] + \".F\" + BXmcXLk[7] + BXmcXLk[9] + BXmcXLk[12] + BXmcXLk[14];" fullword ascii
    $s3  = "var BXmcXLk = \"Sc mCQrRNq r mqkXQyhBW ipting inMipzw yRw ile ETqJDDjiehxZax System gP aHyrv Obj LibtvX ect omOXrOY\".split(\" " ascii
    $s4  = "SfuFM.open(tKMQT,EmARy,false);" fullword ascii
    $s5  = "var XXg = (\"2.XMLHTTP ePhiSEw XbKTB XML ream St riMeVZdl AD WYZXWvn O zroc D\").split(\" \");" fullword ascii
    $s6  = "function ObKXgXOcy(EfjfsrrQqrW) {" fullword ascii
    $s7  = "return jzrnu.status;" fullword ascii
    $s8  = "function HiDW(oGMCk) {" fullword ascii
    $s9  = "return new ActiveXObject(BAJeML);" fullword ascii
    $s10 = "function GDJzgEe(EDAW) {" fullword ascii
    $s11 = "function IfSN(RVePt) {" fullword ascii
    $s12 = "return sYhd.responseBody;" fullword ascii
    $s13 = "if (RVePt == 352-152){return true;} else {return false;}" fullword ascii
    $s14 = "function ZkcJ(MLISF,JkULW) {" fullword ascii
    $s15 = "function UZratbqY(qwe) {" fullword ascii
    $s16 = "if(U>=m.length) {break;}" fullword ascii
    $s17 = "function TIBVC(BAJeML) {" fullword ascii
    $s18 = "function CnGryBAiR(Sjlkd,xVprH,acQBX,rSqh) {" fullword ascii
    $s19 = "function IRDU(SfuFM,EmARy,tKMQT) {" fullword ascii
    $s20 = "if (L >= koFrD.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}