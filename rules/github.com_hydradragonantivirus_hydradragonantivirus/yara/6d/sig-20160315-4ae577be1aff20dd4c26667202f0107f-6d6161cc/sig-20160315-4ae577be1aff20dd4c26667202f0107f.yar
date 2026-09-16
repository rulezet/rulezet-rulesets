rule sig_20160315_4ae577be1aff20dd4c26667202f0107f {
  meta:
    description = "datamaliciousorder - file 20160315_4ae577be1aff20dd4c26667202f0107f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30e655b3d2c371fcc364dbb1d68ba155958efbd00142059ee7f8f01928cfac40"

  strings:
    $s1  = "return OTNZTZZ[0] + OTNZTZZ[2] + OTNZTZZ[4] + \".F\" + OTNZTZZ[7] + OTNZTZZ[9] + OTNZTZZ[12] + OTNZTZZ[14];" fullword ascii
    $s2  = "var UX = true  , DFAp = Jnv[7] + Jnv[9] + Jnv[11];" fullword ascii
    $s3  = "var OTNZTZZ = lBNCG(\"Sc aZLlQOl r vWHLmTobW ipting wuoJJmB Azb ile CxdAgztKknbGFh System iq nOpbJ Obj ltBive ect TGQOogI Wvamu" ascii
    $s4  = "var Jnv = (\"2.XMLHTTP ZNtLvDJ sBmAW XML ream St tcpDNsQV AD mGefrZY O HYWY D\").split(\" \");" fullword ascii
    $s5  = "var OTNZTZZ = lBNCG(\"Sc aZLlQOl r vWHLmTobW ipting wuoJJmB Azb ile CxdAgztKknbGFh System iq nOpbJ Obj ltBive ect TGQOogI Wvamu" ascii
    $s6  = "lujFd.open(XSTgs,KLmxE,false);" fullword ascii
    $s7  = "if (S >= tmFoC.length) {break;}" fullword ascii
    $s8  = "function odNb(gaEgy,dzOcK) {" fullword ascii
    $s9  = "function lzRT(lujFd,KLmxE,XSTgs) {" fullword ascii
    $s10 = "function tVMM(DmiYb) {" fullword ascii
    $s11 = "function dwnk(RYPdi) {" fullword ascii
    $s12 = "function LTCFF(zjmTEJ) {" fullword ascii
    $s13 = "function YzXGFCDPr(vwgcZzSdrWg) {" fullword ascii
    $s14 = "if (LRphJ > 187229-197){return true;} else {return false;}" fullword ascii
    $s15 = "if(I>=x.length) {break;}" fullword ascii
    $s16 = "function Mlxkc(EYvRoI) {" fullword ascii
    $s17 = "function wWfT(GYkVo) {" fullword ascii
    $s18 = "return YTjF.responseBody;" fullword ascii
    $s19 = "function wERK(wCHZP,mNeHh) {" fullword ascii
    $s20 = "return VKzvO.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}