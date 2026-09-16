rule sig_20160321_bddfed065e6bf6640fcd7712a2651771 {
  meta:
    description = "datamaliciousorder - file 20160321_bddfed065e6bf6640fcd7712a2651771.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c1016e22bde5155de680b348be23e0fcfd550e036efa1647f1ab96565a6fa5c"

  strings:
    $s1  = "return WScript.CreateObject(lYaWz);" fullword ascii
    $s2  = "return zwOMENN[0] + zwOMENN[2] + zwOMENN[4] + \".F\" + zwOMENN[7] + zwOMENN[9] + zwOMENN[12] + zwOMENN[14];" fullword ascii
    $s3  = "var eO = true  , IhIM = LLe[7] + LLe[9] + LLe[11];" fullword ascii
    $s4  = "var LLe = (\"2.XMLHTTP dsTUxKj wYIWR XML ream St fEZvuaiX AD tYzrOBT O vpKg D\").split(\" \");" fullword ascii
    $s5  = "lXKtP.open(tzdQQ,biHMw,false);" fullword ascii
    $s6  = "var zwOMENN = TuoxO(UWFfDzasLg+\" \"+\"System Bq LRslS Obj bjQgGZ ect jBPZhaC DXZry\", \" \");" fullword ascii
    $s7  = "if (v >= VBWok.length) {break;}" fullword ascii
    $s8  = "return YEV.size;" fullword ascii
    $s9  = "function pZJE(VBWok) {" fullword ascii
    $s10 = "return riNO.ExpandEnvironmentStrings(MfRbn);" fullword ascii
    $s11 = "return BcVnm.status;" fullword ascii
    $s12 = "return RjV.split(SLveR);" fullword ascii
    $s13 = "function OuEdxqN(riNO,MfRbn) {" fullword ascii
    $s14 = "return KzLClt.position=409-409;" fullword ascii
    $s15 = "OBH = u; break; " fullword ascii
    $s16 = "function ttSbLhr(YoPn) {" fullword ascii
    $s17 = "function nFDSvmkt(YEV) {" fullword ascii
    $s18 = "function BhaqZRkDj(ojBimrylSSI) {" fullword ascii
    $s19 = "function JFUjecXL(FNCn) {" fullword ascii
    $s20 = "if (EqaXD > 197120-441){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}