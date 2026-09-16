rule sig_20160311_7f659dce6927e7dd5f36de791174f014 {
  meta:
    description = "datamaliciousorder - file 20160311_7f659dce6927e7dd5f36de791174f014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6da5b7b437cd1ea0a7236d9c941ddb15a6d036c5903bbce98ede3def0c675fe"

  strings:
    $s1  = "var yw = true  , DNel = Tro[7] + Tro[9] + Tro[11];" fullword ascii
    $s2  = "return lFLgRlW[0] + lFLgRlW[2] + lFLgRlW[4] + \".F\" + lFLgRlW[7] + lFLgRlW[9] + lFLgRlW[12] + lFLgRlW[14];" fullword ascii
    $s3  = "var Tro = (\"2.XMLHTTP nFWSCew rIAyG XML ream St aXlklFCW AD leYCwqq O mBlH D\").split(\" \");" fullword ascii
    $s4  = "zjAzN.open(fumRv,FDlhJ,false);" fullword ascii
    $s5  = "var lFLgRlW = \"Sc OBOQfwp r lUatgclpR ipting GlueBHF jfY ile xAWWEDDZfGfeNN System Ff jNhsu Obj xAczMt ect AfyTWrP\".split(\" " ascii
    $s6  = "Gbn.CreateFolder(lEPa);" fullword ascii
    $s7  = "function duAhZUhi(rZG) {" fullword ascii
    $s8  = "return Hxke.ExpandEnvironmentStrings(mhCPb);" fullword ascii
    $s9  = "function enju(yLjCC) {" fullword ascii
    $s10 = "var lEPa = YEU+cSJdMj[0]+cSJdMj[1];" fullword ascii
    $s11 = "function aKOTVLnam() {" fullword ascii
    $s12 = "function HCgrVcuH(RuDko,oRFVKX) {" fullword ascii
    $s13 = "return rZG.size;" fullword ascii
    $s14 = "function KzNzJ(KklDmi) {" fullword ascii
    $s15 = "if (A >= HEuVg.length) {break;}" fullword ascii
    $s16 = "return yYwvSNZ" fullword ascii
    $s17 = "function ilFX(CUXyv) {" fullword ascii
    $s18 = "return BegI.responseBody;" fullword ascii
    $s19 = "function xkIb(xamoi) {" fullword ascii
    $s20 = "return KnxAChS(yj,CTqZP[912-906]+CTqZP[956-949]+CTqZP[982-974]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}