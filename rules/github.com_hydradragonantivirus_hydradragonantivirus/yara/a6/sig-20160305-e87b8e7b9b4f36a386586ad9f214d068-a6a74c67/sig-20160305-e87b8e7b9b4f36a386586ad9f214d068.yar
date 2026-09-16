rule sig_20160305_e87b8e7b9b4f36a386586ad9f214d068 {
  meta:
    description = "datamaliciousorder - file 20160305_e87b8e7b9b4f36a386586ad9f214d068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "611f5aced1de69b541ce9b89499b38e4d4832c45db7acedb53f64f69ecd19e69"

  strings:
    $s1  = "var yUCoo = \"QXDZcf wbx pt.Shell TtIqDvM Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var pM = true  , XMfs = TrF[7] + \"\" + TrF[9];" fullword ascii
    $s3  = "return wXfFlDb[0] + wXfFlDb[2] + wXfFlDb[4] + \".F\" + wXfFlDb[7] + wXfFlDb[9] + wXfFlDb[12] + wXfFlDb[14];" fullword ascii
    $s4  = "var TrF = (ORB + \"TTP\" + \" liWUIKa eBOgI XML ream St eRIUNBAb AD RIcliZf OD\").split(\" \");" fullword ascii
    $s5  = "var wXfFlDb = \"Sc DSXIivo r NzVmSyhpB ipting EpDUQjS ysn ile cZbzvZdpedZKFL System FO MLGLs Obj WTCJpP ect zInWLPe\".split(\" " ascii
    $s6  = "dXboA.open(GJGkF,RqvuO,false);" fullword ascii
    $s7  = "function GFBX(sRJzR) {" fullword ascii
    $s8  = "function RCknAtI(ttaI) {" fullword ascii
    $s9  = "if (((new Date())>0,7631924888)) {" fullword ascii
    $s10 = "function TNZaYWED() {" fullword ascii
    $s11 = "function hpdtfZmhf(MjvQGQFTAKl) {" fullword ascii
    $s12 = "return SRHA.responseBody;" fullword ascii
    $s13 = "function bJcy(tPVss) {" fullword ascii
    $s14 = "function gTuM(PkgXe,pffYK) {" fullword ascii
    $s15 = "function hlPG(eyFNL) {" fullword ascii
    $s16 = "function DUQf(dXboA,RqvuO,GJGkF) {" fullword ascii
    $s17 = "function SkYy(hEMRg) {" fullword ascii
    $s18 = "function XwoMk(gJbpcx) {" fullword ascii
    $s19 = "return WjLqpeQ" fullword ascii
    $s20 = "function YPYlQzR(SRHA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}