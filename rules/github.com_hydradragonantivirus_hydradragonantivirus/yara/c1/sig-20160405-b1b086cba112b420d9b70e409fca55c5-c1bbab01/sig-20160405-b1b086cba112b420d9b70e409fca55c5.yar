rule sig_20160405_b1b086cba112b420d9b70e409fca55c5 {
  meta:
    description = "datamaliciousorder - file 20160405_b1b086cba112b420d9b70e409fca55c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ac795ddbb5b4469c874430938d0af5e5530cc95bb3856ad3d9d0d9430930af3"

  strings:
    $s1  = "function vgEYEtCbC(GoDKKLuBqRx) {" fullword ascii
    $s2  = "var TM = true  , eChG = ATU[7] + ATU[9] + ATU[11];" fullword ascii
    $s3  = "return oblIJaZ[0] + oblIJaZ[2] + oblIJaZ[4] + \".F\" + oblIJaZ[7] + oblIJaZ[9] + oblIJaZ[12] + oblIJaZ[14];" fullword ascii
    $s4  = "hhsd.open(evcVS,JuAHx,false);" fullword ascii
    $s5  = "var ATU = (\"2.XMLHTTP xKCQlTw tPlXP XML ream St tilhyMWu AD kRmnIlo O zuhU D\").split(\" \");" fullword ascii
    $s6  = "function VoRHUjGu(kPGL) {" fullword ascii
    $s7  = "return cNJC;" fullword ascii
    $s8  = "function PJuXA(KjZ,WfbXD) {" fullword ascii
    $s9  = "function xFSM(MRyBX) {" fullword ascii
    $s10 = "return new ActiveXObject(QKco);" fullword ascii
    $s11 = "return rzcmZ.status;" fullword ascii
    $s12 = "var gxjbIHn = \"RgSwpt*UtG*pt.S\"+\"hell*dQLUgNJ*Scri*\";" fullword ascii
    $s13 = "function XWBM(FNfUx) {" fullword ascii
    $s14 = "return Yuefr;" fullword ascii
    $s15 = "function lQtXsG(kZvnimO) {" fullword ascii
    $s16 = "function yQAA(JXCPK) {" fullword ascii
    $s17 = "function BgUVkSw(fkjU) {" fullword ascii
    $s18 = "return KjZ.split(WfbXD);" fullword ascii
    $s19 = "function yZBjo(gXqthW) {" fullword ascii
    $s20 = "function uqdZeGVLG(qYpHE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}