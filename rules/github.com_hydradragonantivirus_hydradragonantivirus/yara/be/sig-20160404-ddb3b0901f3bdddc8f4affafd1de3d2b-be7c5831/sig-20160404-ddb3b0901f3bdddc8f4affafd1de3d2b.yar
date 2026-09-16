rule sig_20160404_ddb3b0901f3bdddc8f4affafd1de3d2b {
  meta:
    description = "datamaliciousorder - file 20160404_ddb3b0901f3bdddc8f4affafd1de3d2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc72c5e1a392be9e968bd42d4d2cb70c6204c269dd4609c7752a0f0e0587ba60"

  strings:
    $s1  = "var KD = true  , GWPF = SMX[7] + SMX[9] + SMX[11];" fullword ascii
    $s2  = "return AHFbsNi[0] + AHFbsNi[2] + AHFbsNi[4] + \".F\" + AHFbsNi[7] + AHFbsNi[9] + AHFbsNi[12] + AHFbsNi[14];" fullword ascii
    $s3  = "var AHFbsNi = QnoIU(veREOXzDqn+\" \"+\"System Qk pPRHt Obj HdBiXT ect WLwPzNt rjlVG\", \" \");" fullword ascii
    $s4  = "var SMX = (\"2.XMLHTTP tFjLIrJ rRmSm XML ream St ChUfcgNq AD RFZRroe O vAEm D\").split(\" \");" fullword ascii
    $s5  = "AHPk.open(ZUhLT,DMvdq,false);" fullword ascii
    $s6  = "if(i>=q.length) {break;}" fullword ascii
    $s7  = "return OvEn[JAgphM[0]];" fullword ascii
    $s8  = "function dIPBMLb(OvEn) {" fullword ascii
    $s9  = "function QnoIU(JIE,XdRoN) {" fullword ascii
    $s10 = "function mjzQwJ(RBVk,cKBXKK) {" fullword ascii
    $s11 = "function QLRT(gbHwT,vWHsT) {" fullword ascii
    $s12 = "return UVnwCnH(QA,PdqxE[571-565]+PdqxE[416-409]+PdqxE[1003-995]);" fullword ascii
    $s13 = "function aCVLvaQr(diw) {" fullword ascii
    $s14 = "return JIE.split(XdRoN);" fullword ascii
    $s15 = "function FxznV(zBOooN) {" fullword ascii
    $s16 = "return NhDN;" fullword ascii
    $s17 = "var PetTkAP = \"TJNDgO*nPM*pt.S\"+\"hell*AraoVhm*Scri*\";" fullword ascii
    $s18 = "return diw.size;" fullword ascii
    $s19 = "function noMqOpZEw(JVMJU) {" fullword ascii
    $s20 = "function MyqaEmTJW(eKOZVpGIMFb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}