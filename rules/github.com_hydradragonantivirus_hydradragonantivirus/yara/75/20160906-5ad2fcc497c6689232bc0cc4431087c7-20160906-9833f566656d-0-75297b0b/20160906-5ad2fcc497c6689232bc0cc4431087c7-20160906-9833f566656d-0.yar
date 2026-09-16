rule _20160906_5ad2fcc497c6689232bc0cc4431087c7_20160906_9833f566656d_0 {
  meta:
    description = "datamaliciousorder - from files 20160906_5ad2fcc497c6689232bc0cc4431087c7.js, 20160906_9833f566656dceb29a397c4b5ad7da0c.js, 20160906_e5db5dab799b56b23389fce5394bdca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dedde1eb6fbddf8081a39080bc4ed1c3667a5616d6c0fb75f036efce48e5d00"
    hash2       = "f65f039fc2a1a383e9070ef4bc8e2b30b03b539edd587194b173a0d63370d9c3"
    hash3       = "f922e5c7c8fc398277f70230ea67f912e13ca9c691595d4304deaeeb998aceeb"

  strings:
    $s1  = "function uI(RQv, vG, P, yMv)" fullword ascii
    $s2  = "function zJM(Aqd)" fullword ascii
    $s3  = "function udI(T)" fullword ascii
    $s4  = "return Zau;" fullword ascii
    $s5  = "function fK(Aqd, vG, P, yMv)" fullword ascii
    $s6  = "return gvx;" fullword ascii
    $s7  = "return PTm == hOE;" fullword ascii
    $s8  = "function OdW(cN)" fullword ascii
    $s9  = "return vM;" fullword ascii
    $s10 = "function TU()" fullword ascii
    $s11 = "return (zJM(rI));" fullword ascii
    $s12 = "function UN(Aqd, vG)" fullword ascii
    $s13 = "return fK(hR, vG, P, yMv);" fullword ascii
    $s14 = "return DYk;" fullword ascii
    $s15 = "function phi (UqU)" fullword ascii
    $s16 = "return (UN(rI, vG));" fullword ascii
    $s17 = "return uI(zuC, vG, P, xew);" fullword ascii
    $s18 = "var gvx = String[j](UqU);" fullword ascii
    $s19 = "return (fK(rI, vG, P, yMv));" fullword ascii
    $s20 = "catch (B)" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}