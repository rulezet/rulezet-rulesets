rule sig_20160315_1c78914586f083b0c7dec04d54bb90f6 {
  meta:
    description = "datamaliciousorder - file 20160315_1c78914586f083b0c7dec04d54bb90f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "495c485b20271f89fbcc67bef95aabaffa42792681d4d0322e34b831262c90c7"

  strings:
    $s1  = "var eZ = true  , havk = yxA[7] + yxA[9] + yxA[11];" fullword ascii
    $s2  = "return igclyWR[0] + igclyWR[2] + igclyWR[4] + \".F\" + igclyWR[7] + igclyWR[9] + igclyWR[12] + igclyWR[14];" fullword ascii
    $s3  = "var igclyWR = VjSwU(\"Sc uXBoxHz r uQjxCWRfB ipting xfsnitf dpO ile dezPaLzSfOTUro System GY TCmOs Obj yZBTyT ect CRzisge YIfgE" ascii
    $s4  = "var yxA = (\"2.XMLHTTP hRvWQOt GUbfd XML ream St iYSYAYIg AD yGXjGVb O YXQy D\").split(\" \");" fullword ascii
    $s5  = "var igclyWR = VjSwU(\"Sc uXBoxHz r uQjxCWRfB ipting xfsnitf dpO ile dezPaLzSfOTUro System GY TCmOs Obj yZBTyT ect CRzisge YIfgE" ascii
    $s6  = "fQTlI.open(oizDP,kDoRE,false);" fullword ascii
    $s7  = "function BLTMP(xlpPap) {" fullword ascii
    $s8  = "function tCPDxDwo(HLD) {" fullword ascii
    $s9  = "return MaSHK;" fullword ascii
    $s10 = "function gawj(tLSFG,bPMdE) {" fullword ascii
    $s11 = "function zkDRh(bSBAFM) {" fullword ascii
    $s12 = "function lCeL(dNzmG) {" fullword ascii
    $s13 = "return GOT.split(xiWBa);" fullword ascii
    $s14 = "function XpAaIjU(mncR,CgawD) {" fullword ascii
    $s15 = "return XpAaIjU(pO,snHVm[970-964]+snHVm[820-813]+snHVm[888-880]);" fullword ascii
    $s16 = "function KosO(blSAF) {" fullword ascii
    $s17 = "function FujrjQzcd(nDKBI) {" fullword ascii
    $s18 = "return HLD.size;" fullword ascii
    $s19 = "if (WxIbn == 425-225){return true;} else {return false;}" fullword ascii
    $s20 = "function KRwb(iYHPe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}