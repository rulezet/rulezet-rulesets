rule sig_20160405_4d078cbdeb22bde0469c99a271e5cee4 {
  meta:
    description = "datamaliciousorder - file 20160405_4d078cbdeb22bde0469c99a271e5cee4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc46eb71ca8d2c81af8e3e52e124b91d30e6b5b93dea2335ce529a476852401"

  strings:
    $s1  = "return DWKWbLc[0] + DWKWbLc[2] + DWKWbLc[4] + \".F\" + DWKWbLc[7] + DWKWbLc[9] + DWKWbLc[12] + DWKWbLc[14];" fullword ascii
    $s2  = "var UC = true  , MnhG = WtM[7] + WtM[9] + WtM[11];" fullword ascii
    $s3  = "uSUF.open(GURWX,fRcwc,false);" fullword ascii
    $s4  = "var WtM = (\"2.XMLHTTP JroPxOx syDds XML ream St bsQbDaqr AD whlxniE O XGMd D\").split(\" \");" fullword ascii
    $s5  = "return lbv.size;" fullword ascii
    $s6  = "function wqbm(SdgDi,drKll) {" fullword ascii
    $s7  = "return Pgw.split(hWcgg);" fullword ascii
    $s8  = "function ABsH(IZZhu) {" fullword ascii
    $s9  = "function tFHs(kaqBT,StxQa) {" fullword ascii
    $s10 = "function ZdHAS(lqEkeW) {" fullword ascii
    $s11 = "function NrbY(bIZIh) {" fullword ascii
    $s12 = "function kGCUh(xUmvdOrU,WbJO) {" fullword ascii
    $s13 = "ddp = l; break; " fullword ascii
    $s14 = "function TitzP(UXkvFS) {" fullword ascii
    $s15 = "function CrYfVFn(lRlI,XyTkJ) {" fullword ascii
    $s16 = "if (YWftA == 301-101){return true;} else {return false;}" fullword ascii
    $s17 = "function smhLNUQ(zdyW) {" fullword ascii
    $s18 = "function GJGe(MNPEz) {" fullword ascii
    $s19 = "function iQpeU(Pgw,hWcgg) {" fullword ascii
    $s20 = "function ZkBm(YWftA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}