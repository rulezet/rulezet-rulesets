rule sig_20160310_ae69e8c6b6e58ce4a7e87ac61489958e {
  meta:
    description = "datamaliciousorder - file 20160310_ae69e8c6b6e58ce4a7e87ac61489958e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508a370bcf52561e284fe6b9387075c728f0464298781def7ec98726ea3c6c7a"

  strings:
    $s1  = "return ngsPKhu[0] + ngsPKhu[2] + ngsPKhu[4] + \".F\" + ngsPKhu[7] + ngsPKhu[9] + ngsPKhu[12] + ngsPKhu[14];" fullword ascii
    $s2  = "var VG = true  , OVRf = ggE[7] + ggE[9] + ggE[11];" fullword ascii
    $s3  = "var ggE = (\"2.XMLHTTP TsLvgwb VeRjA XML ream St EBFGzVux AD qRFFoQB O cSda D\").split(\" \");" fullword ascii
    $s4  = "var ngsPKhu = \"Sc BvLponN r HoDRqklyC ipting iheezbV WJt ile YYDGNHFKQUXMJM System Sl FWipF Obj wAMSMP ect gqJTxHu\".split(\" " ascii
    $s5  = "vSkGU.open(YiKNZ,UHnTT,false);" fullword ascii
    $s6  = "function wIMl(pZbDC) {" fullword ascii
    $s7  = "function WHUVsNo(oGhF,rVmEs) {" fullword ascii
    $s8  = "function gHRI(qqBGI) {" fullword ascii
    $s9  = "return OWgN.responseBody;" fullword ascii
    $s10 = "function HbppuEqF(VtDOJ,glruGq) {" fullword ascii
    $s11 = "return oGhF.ExpandEnvironmentStrings(rVmEs);" fullword ascii
    $s12 = "function NQYuuBz(OWgN) {" fullword ascii
    $s13 = "if (n >= pZbDC.length) {break;}" fullword ascii
    $s14 = "return XdhNq;" fullword ascii
    $s15 = "function EdOS(vSkGU,UHnTT,YiKNZ) {" fullword ascii
    $s16 = "function niDPTEfKG(EIOetcEeIgm) {" fullword ascii
    $s17 = "return aOw.size;" fullword ascii
    $s18 = "return new ActiveXObject(MxGRJa);" fullword ascii
    $s19 = "if (votuJ > 154703-412){return true;} else {return false;}" fullword ascii
    $s20 = "function SFVM(kGAoG,wziBd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}