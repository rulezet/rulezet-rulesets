rule sig_20160324_468d09563fd5fabab778cd339c24d757 {
  meta:
    description = "datamaliciousorder - file 20160324_468d09563fd5fabab778cd339c24d757.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c971d668b59930ecec4c9ea348db23116372d811d4e013b8ef04262cb6e4cd71"

  strings:
    $s1  = "return WScript.CreateObject(HoxLV);" fullword ascii
    $s2  = "return bMvSjxT[0] + bMvSjxT[2] + bMvSjxT[4] + \".F\" + bMvSjxT[7] + bMvSjxT[9] + bMvSjxT[12] + bMvSjxT[14];" fullword ascii
    $s3  = "var po = true  , FXiM = YLk[7] + YLk[9] + YLk[11];" fullword ascii
    $s4  = "Quuq.open(npoif,zBaVY,false);" fullword ascii
    $s5  = "var YLk = (\"2.XMLHTTP ZlruSQS KLfJa XML ream St oMeMKPUE AD rXmwDOC O HHWB D\").split(\" \");" fullword ascii
    $s6  = "var bMvSjxT = cThmB(tDDDBeavlx+\" \"+\"System FU ozYPP Obj WRGWbj ect BAMjRdr PsVYN\", \" \");" fullword ascii
    $s7  = "function CoOw(YrdPm) {" fullword ascii
    $s8  = "if (YrdPm > 189191-296){return true;} else {return false;}" fullword ascii
    $s9  = "function DztOJCq(UQTz,GzehL) {" fullword ascii
    $s10 = "function KpqeQon(YaIq) {" fullword ascii
    $s11 = "function dhRY(rYlJV) {" fullword ascii
    $s12 = "function uwVPkaIRj(elRTfbWTouy) {" fullword ascii
    $s13 = "function FQdu(HoxLV) {" fullword ascii
    $s14 = "function hVddE(ElNfXa) {" fullword ascii
    $s15 = "RBA = u; break; " fullword ascii
    $s16 = "return YaIq[ebwdDC[0]];" fullword ascii
    $s17 = "if(u>=d.length) {break;}" fullword ascii
    $s18 = "function UxQZR(XSzHmh) {" fullword ascii
    $s19 = "function cThmB(UHE,LvJwj) {" fullword ascii
    $s20 = "return rYlJV.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}