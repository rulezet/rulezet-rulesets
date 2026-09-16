rule sig_20160404_db70bc8df8b7fec45c94c45aefb93a84 {
  meta:
    description = "datamaliciousorder - file 20160404_db70bc8df8b7fec45c94c45aefb93a84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec047bd6496c842cb13a9dc6fe5f6d4be3f38ca453ef26024d01ac3aa77c7977"

  strings:
    $s1  = "var gc = true  , NOTa = SgD[7] + SgD[9] + SgD[11];" fullword ascii
    $s2  = "return YlRoIyC[0] + YlRoIyC[2] + YlRoIyC[4] + \".F\" + YlRoIyC[7] + YlRoIyC[9] + YlRoIyC[12] + YlRoIyC[14];" fullword ascii
    $s3  = "var YlRoIyC = dMNpn(WVfgfPMBQi+\" \"+\"System sw tLoeS Obj zVOaTe ect NWmigsX TSEmN\", \" \");" fullword ascii
    $s4  = "vXIn.open(GPHrp,ddyfe,false);" fullword ascii
    $s5  = "var SgD = (\"2.XMLHTTP KROqaCd urrKD XML ream St ACLioTKH AD qVGEdiJ O GgQm D\").split(\" \");" fullword ascii
    $s6  = "function VVWB(ttKNe,ddyfe,GPHrp) {" fullword ascii
    $s7  = "function XpduWf(HkIrYfr) {" fullword ascii
    $s8  = "function uAVQ(agVho,lIWAC) {" fullword ascii
    $s9  = "if(f>=q.length) {break;}" fullword ascii
    $s10 = "return new ActiveXObject(YUIf);" fullword ascii
    $s11 = "function pJHNhhWZK(hfyCD) {" fullword ascii
    $s12 = "return fWfDRIZ(ur,MiowV[290-284]+MiowV[147-140]+MiowV[485-477]);" fullword ascii
    $s13 = "return PRon;" fullword ascii
    $s14 = "var ToglkpT = \"eJIsXR*KrV*pt.S\"+\"hell*TTOpEaa*Scri*\";" fullword ascii
    $s15 = "return nfT.split(wAJsP);" fullword ascii
    $s16 = "function glFk(mOxqs) {" fullword ascii
    $s17 = "function NlKe(JFtRC) {" fullword ascii
    $s18 = "function ELAod(qpLcII) {" fullword ascii
    $s19 = "return \"MAkXhIeGQsvPUs\";" fullword ascii
    $s20 = "return Jel.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}