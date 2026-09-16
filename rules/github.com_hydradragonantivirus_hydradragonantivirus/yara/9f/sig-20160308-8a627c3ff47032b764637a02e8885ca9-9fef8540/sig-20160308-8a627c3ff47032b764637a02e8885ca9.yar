rule sig_20160308_8a627c3ff47032b764637a02e8885ca9 {
  meta:
    description = "datamaliciousorder - file 20160308_8a627c3ff47032b764637a02e8885ca9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e0932af0df6f9714ba54daaea173b498d3257b3bc3d487b29be704f9e989878"

  strings:
    $s1  = "return JTlhMFD[0] + JTlhMFD[2] + JTlhMFD[4] + \".F\" + JTlhMFD[7] + JTlhMFD[9] + JTlhMFD[12] + JTlhMFD[14];" fullword ascii
    $s2  = "var To = true  , Mqms = UxL[7] + UxL[9] + UxL[11];" fullword ascii
    $s3  = "yHp.CreateFolder(bevy);" fullword ascii
    $s4  = "GjTIZ.open(lXmsu,EMRvd,false);" fullword ascii
    $s5  = "var UxL = (\"2.XMLHTTP KCVHPhz mstpT XML ream St VwKJPIgS AD JGIllNp O rAFr D\").split(\" \");" fullword ascii
    $s6  = "function GTFeLRB(GfdE) {" fullword ascii
    $s7  = "function yfyV(dvdxy) {" fullword ascii
    $s8  = "function vqGh(fHHRQ) {" fullword ascii
    $s9  = "function covN(pjfbq) {" fullword ascii
    $s10 = "function oUYozyVHw(YrKHPGkXSlT) {" fullword ascii
    $s11 = "function QaRngPJct(hSiLA,KlAjZ,yACJa,iNMk) {" fullword ascii
    $s12 = "function UcNUfQre() {" fullword ascii
    $s13 = "if(Z>=d.length) {break;}" fullword ascii
    $s14 = "function IKGr(kYjvt) {" fullword ascii
    $s15 = "if (u >= pjfbq.length) {break;}" fullword ascii
    $s16 = "function BjwH(KDSDL,UuQiN) {" fullword ascii
    $s17 = "var bevy = rMu+lWwOdk[0]+lWwOdk[1];" fullword ascii
    $s18 = "function ziud(jsgUk) {" fullword ascii
    $s19 = "return hOvAa;" fullword ascii
    $s20 = "if (AqAxy > 175145-629){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}