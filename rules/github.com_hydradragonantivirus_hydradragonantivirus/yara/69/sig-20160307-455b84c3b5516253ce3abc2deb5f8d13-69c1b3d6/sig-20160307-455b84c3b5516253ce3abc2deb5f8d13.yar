rule sig_20160307_455b84c3b5516253ce3abc2deb5f8d13 {
  meta:
    description = "datamaliciousorder - file 20160307_455b84c3b5516253ce3abc2deb5f8d13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01b91c6f854904e60d1e0bbedbad091b36b5003d626f0b5bb556aeb13bb4a8c1"

  strings:
    $s1  = "return XDDZtTU[0] + XDDZtTU[2] + XDDZtTU[4] + \".F\" + XDDZtTU[7] + XDDZtTU[9] + XDDZtTU[12] + XDDZtTU[14];" fullword ascii
    $s2  = "var CT = true  , fCnw = JzR[7] + JzR[9] + JzR[11];" fullword ascii
    $s3  = "var JzR = (\"2.XMLHTTP SqgvReo mkKxD XML ream St gqabHJCC AD QuwUzfz O XslN D\").split(\" \");" fullword ascii
    $s4  = "XjOJZ.open(AXBeU,gBjjc,false);" fullword ascii
    $s5  = "var XDDZtTU = \"Sc oAXwSIA r dGcNvwfjZ ipting RhAyecw Lee ile SXhpkkvLxeYRFW System zg djlOV Obj kARvBq ect cGEkUCP\".split(\" " ascii
    $s6  = "function MEMu(oToXF,iRSXU) {" fullword ascii
    $s7  = "function nODp(CIInD) {" fullword ascii
    $s8  = "function tKix(dIoIR) {" fullword ascii
    $s9  = "function sHmF(UZoGp) {" fullword ascii
    $s10 = "if (((new Date())>0,74608888)) {" fullword ascii
    $s11 = "function maLyiUVTF(krUGzGlBwsE) {" fullword ascii
    $s12 = "return PG.ExpandEnvironmentStrings(BXRKe[6]+BXRKe[7]+BXRKe[8]);" fullword ascii
    $s13 = "function Nfqf(yOzzB) {" fullword ascii
    $s14 = "if (SWhWH > 182895-741){return true;} else {return false;}" fullword ascii
    $s15 = "function KmFfd(LIUnBX) {" fullword ascii
    $s16 = "function ImUs(tJrhG) {" fullword ascii
    $s17 = "function JmPg(SWhWH) {" fullword ascii
    $s18 = "return new ActiveXObject(LIUnBX);" fullword ascii
    $s19 = "yqO = D; break; " fullword ascii
    $s20 = "function TPUA(XjOJZ,gBjjc,AXBeU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}