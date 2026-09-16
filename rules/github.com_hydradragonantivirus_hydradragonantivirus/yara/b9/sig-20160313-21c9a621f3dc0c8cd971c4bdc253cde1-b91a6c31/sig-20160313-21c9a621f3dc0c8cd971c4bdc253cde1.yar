rule sig_20160313_21c9a621f3dc0c8cd971c4bdc253cde1 {
  meta:
    description = "datamaliciousorder - file 20160313_21c9a621f3dc0c8cd971c4bdc253cde1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2320f7baa3225e68aa6d7c7391645fcac5536cda8230a99983b683378a24f19"

  strings:
    $s1  = "return vLdiflT[0] + vLdiflT[2] + vLdiflT[4] + \".F\" + vLdiflT[7] + vLdiflT[9] + vLdiflT[12] + vLdiflT[14];" fullword ascii
    $s2  = "var cg = true  , UCyt = AAz[7] + AAz[9] + AAz[11];" fullword ascii
    $s3  = "var vLdiflT = \"Sc sYqtrsq r HJdmCBztw ipting wJBAIzS Czb ile FIKZofyuvTNqMI System sc CqQnB Obj mqRuNG ect AWbDxCC\".split(\" " ascii
    $s4  = "var AAz = (\"2.XMLHTTP igtVPgs jkplq XML ream St uISYZuKa AD xoSIQEo O Qcsx D\").split(\" \");" fullword ascii
    $s5  = "zuraP.open(wdkLB,PLKGn,false);" fullword ascii
    $s6  = "function XQNJ(OfAjc) {" fullword ascii
    $s7  = "function TRSw(zuraP,PLKGn,wdkLB) {" fullword ascii
    $s8  = "function HBtSx(iBqpAD) {" fullword ascii
    $s9  = "return xDI.size;" fullword ascii
    $s10 = "function ylgd(yyFOY) {" fullword ascii
    $s11 = "if (mbYgv > 181738-100){return true;} else {return false;}" fullword ascii
    $s12 = "return yyFOY.status;" fullword ascii
    $s13 = "function Buov(zIFZj) {" fullword ascii
    $s14 = "return bhqEX;" fullword ascii
    $s15 = "function EwUcWNR(nIhV,AcNjl) {" fullword ascii
    $s16 = "function Iulf(tuBQI) {" fullword ascii
    $s17 = "return EwUcWNR(fw,RBFKG[266-260]+RBFKG[666-659]+RBFKG[639-631]);" fullword ascii
    $s18 = "function alKe(wtTAv) {" fullword ascii
    $s19 = "function FBYKuKoQF(VNaYimUjxbj) {" fullword ascii
    $s20 = "function NFDpk(HiSjUk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}