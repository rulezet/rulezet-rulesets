rule sig_20160404_4fe28fe443d365dbf3ca0732bd0b77e7 {
  meta:
    description = "datamaliciousorder - file 20160404_4fe28fe443d365dbf3ca0732bd0b77e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8bb004bfb18317fe6e4aa055d02e0003ad7c3a4831741375d5802fcba1949ed"

  strings:
    $s1  = "return VAWfEBO[0] + VAWfEBO[2] + VAWfEBO[4] + \".F\" + VAWfEBO[7] + VAWfEBO[9] + VAWfEBO[12] + VAWfEBO[14];" fullword ascii
    $s2  = "var VAWfEBO = FLMHu(JUKNnPACEl+\" \"+\"System oz RBCxL Obj iioNQT ect umHNpEN HOIJo\", \" \");" fullword ascii
    $s3  = "fgmy.open(POadc,VeCpX,false);" fullword ascii
    $s4  = "var VES = (\"2.XMLHTTP UnEEzWe cKeoE XML ream St JSbUBoyQ AD WHYboyR O OEzN D\").split(\" \");" fullword ascii
    $s5  = "function mKQY(HGXjg) {" fullword ascii
    $s6  = "var yy = true  , oCRL = VES[7] + VES[9] + VES[11];" fullword ascii
    $s7  = "function xTaPem(ooQE,KfVNGQ) {" fullword ascii
    $s8  = "function wakA(zUiCg) {" fullword ascii
    $s9  = "function vxiuHpN(DMCr) {" fullword ascii
    $s10 = "return DMCr[rTASwj[0]];" fullword ascii
    $s11 = "function eeGj(zTmJZ,VeCpX,POadc) {" fullword ascii
    $s12 = "return MRLOk;" fullword ascii
    $s13 = "function hCIth(jutoFy) {" fullword ascii
    $s14 = "function IsxmgYWZa(SRWhc) {" fullword ascii
    $s15 = "if(K>=l.length) {break;}" fullword ascii
    $s16 = "return bFkFHMl;" fullword ascii
    $s17 = "function iutd(FjnQJ) {" fullword ascii
    $s18 = "return EIW.size;" fullword ascii
    $s19 = "function hJscHQdPw(GEuBYPcXnSe) {" fullword ascii
    $s20 = "return \"uCGIDXOXlqmtOQ\";" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}