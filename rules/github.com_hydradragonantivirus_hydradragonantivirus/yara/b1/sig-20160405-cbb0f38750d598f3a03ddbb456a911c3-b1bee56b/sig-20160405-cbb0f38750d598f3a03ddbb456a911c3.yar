rule sig_20160405_cbb0f38750d598f3a03ddbb456a911c3 {
  meta:
    description = "datamaliciousorder - file 20160405_cbb0f38750d598f3a03ddbb456a911c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd237be1595a630fa8c53c7e44b510979d21baedf6d19009957c08bb402f12f0"

  strings:
    $s1  = "return bpthvyk[0] + bpthvyk[2] + bpthvyk[4] + \".F\" + bpthvyk[7] + bpthvyk[9] + bpthvyk[12] + bpthvyk[14];" fullword ascii
    $s2  = "var Cq = true  , schS = Nsz[7] + Nsz[9] + Nsz[11];" fullword ascii
    $s3  = "DYFY.open(bwxQA,SNoGG,false);" fullword ascii
    $s4  = "var Nsz = (\"2.XMLHTTP ssDZJZz kFWxt XML ream St LjvraWIK AD wyDBfhz O RMIj D\").split(\" \");" fullword ascii
    $s5  = "function TiOGbvOG(unoG) {" fullword ascii
    $s6  = "function vxFC(yeLQB,YzjNF) {" fullword ascii
    $s7  = "function KtZWg(jMqczK) {" fullword ascii
    $s8  = "function yIdBOV(MqYFeEL) {" fullword ascii
    $s9  = "return \"BJjYyFmehiUPdb\";" fullword ascii
    $s10 = "function znUb(svaQY,SNoGG,bwxQA) {" fullword ascii
    $s11 = "function rRhIxGzt(ODe) {" fullword ascii
    $s12 = "function dUxOI(xmw,mcpdr) {" fullword ascii
    $s13 = "if (KzXPX > 171787-226){return true;} else {return false;}" fullword ascii
    $s14 = "function FmTa(MedBf) {" fullword ascii
    $s15 = "function pfmA(dADIS) {" fullword ascii
    $s16 = "function EeHy(dbLjP) {" fullword ascii
    $s17 = "return kospAwh[0];" fullword ascii
    $s18 = "function XZqYtT(wEqX,jGAawF) {" fullword ascii
    $s19 = "function ArCv(ftkqA) {" fullword ascii
    $s20 = "function uyvLW(PJTpYQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}