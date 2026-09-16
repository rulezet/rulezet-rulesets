rule sig_20160321_6222ef2406441e6fe333e539e25e5296 {
  meta:
    description = "datamaliciousorder - file 20160321_6222ef2406441e6fe333e539e25e5296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22ea6663a2a3ff0bd820cb2f7bb77e28ceea3ef4412e07c0bb6334c73b1ec446"

  strings:
    $s1  = "return WScript.CreateObject(POFTi);" fullword ascii
    $s2  = "return ikrctpB[0] + ikrctpB[2] + ikrctpB[4] + \".F\" + ikrctpB[7] + ikrctpB[9] + ikrctpB[12] + ikrctpB[14];" fullword ascii
    $s3  = "var JT = true  , AuFb = tRx[7] + tRx[9] + tRx[11];" fullword ascii
    $s4  = "var tRx = (\"2.XMLHTTP tMVCKcx KzgLB XML ream St FJwYutXp AD zFLZDrh O jQWb D\").split(\" \");" fullword ascii
    $s5  = "gsTTe.open(bbtSU,HosZC,false);" fullword ascii
    $s6  = "var ikrctpB = POEas(oOmHCMYwrl+\" \"+\"System jH bomUe Obj yBTtIF ect xhiVDlb ezRRj\", \" \");" fullword ascii
    $s7  = "if(H>=j.length) {break;}" fullword ascii
    $s8  = "function OPlXWtHxz(CDcRYmqdxzo) {" fullword ascii
    $s9  = "function WRUr(WzFQD) {" fullword ascii
    $s10 = "function bhYOGzv(oRbA,qGFSZ) {" fullword ascii
    $s11 = "return new ActiveXObject(HNIdBA);" fullword ascii
    $s12 = "function xePsBgmN(EGt) {" fullword ascii
    $s13 = "if (AtVCl == 848-648){return true;} else {return false;}" fullword ascii
    $s14 = "function Ibhl(YslGL) {" fullword ascii
    $s15 = "return bhYOGzv(lY,HvBQV[810-804]+HvBQV[521-514]+HvBQV[553-545]);" fullword ascii
    $s16 = "return oRbA.ExpandEnvironmentStrings(qGFSZ);" fullword ascii
    $s17 = "function QFdF(POFTi) {" fullword ascii
    $s18 = "function haQv(vrzyg) {" fullword ascii
    $s19 = "function zYaZt(UVMukg) {" fullword ascii
    $s20 = "function kIaCLSDB(VUde) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}