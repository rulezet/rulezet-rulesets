rule sig_20160324_31f4735090eeb8213e970c77f6474954 {
  meta:
    description = "datamaliciousorder - file 20160324_31f4735090eeb8213e970c77f6474954.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "690b9f8a363a24b8f256341294c290f0a2d87f679c1de1fa931ef7b34c25e7ff"

  strings:
    $s1  = "return WScript.CreateObject(Jlsdp);" fullword ascii
    $s2  = "return UWPvVUv[0] + UWPvVUv[2] + UWPvVUv[4] + \".F\" + UWPvVUv[7] + UWPvVUv[9] + UWPvVUv[12] + UWPvVUv[14];" fullword ascii
    $s3  = "var Cn = true  , GOOS = hVT[7] + hVT[9] + hVT[11];" fullword ascii
    $s4  = "var hVT = (\"2.XMLHTTP qwfpRda rfxgq XML ream St GhtsdFyu AD MUBEeCk O iOgn D\").split(\" \");" fullword ascii
    $s5  = "Vxvp.open(QgzIg,TVvkW,false);" fullword ascii
    $s6  = "var UWPvVUv = ftZvp(kfcnkcuHcX+\" \"+\"System tQ fwgRo Obj WwYAlw ect fFIjfyO ITiyN\", \" \");" fullword ascii
    $s7  = "if(g>=m.length) {break;}" fullword ascii
    $s8  = "function MYJiIcEA(VpD) {" fullword ascii
    $s9  = "function djoB(VQPye) {" fullword ascii
    $s10 = "function hlIN(iovRZ) {" fullword ascii
    $s11 = "if (t >= ekFjy.length) {break;}" fullword ascii
    $s12 = "var uyppBlj = \"rMqFsT*BJU*pt.S\"+\"hell*WubmguW*Scri*\";" fullword ascii
    $s13 = "function Yvgt(nMCfI,REUUG) {" fullword ascii
    $s14 = "function crZnM(nUCsaflp,lwsP) {" fullword ascii
    $s15 = "if (qhnQP > 182982-246){return true;} else {return false;}" fullword ascii
    $s16 = "function bkCn(EJajd) {" fullword ascii
    $s17 = "return CUBA.ExpandEnvironmentStrings(CUCQM);" fullword ascii
    $s18 = "return MMXIim/*U0ZwqFojjBXip0BFkzzcyKtE8*/.position=783-783;" fullword ascii
    $s19 = "function ILGUGSzlC(qzYHmtMdTJE) {" fullword ascii
    $s20 = "function hsqI(pOJRr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}