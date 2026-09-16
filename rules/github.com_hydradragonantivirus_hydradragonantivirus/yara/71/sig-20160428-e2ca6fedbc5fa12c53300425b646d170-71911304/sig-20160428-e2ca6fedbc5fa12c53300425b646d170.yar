rule sig_20160428_e2ca6fedbc5fa12c53300425b646d170 {
  meta:
    description = "datamaliciousorder - file 20160428_e2ca6fedbc5fa12c53300425b646d170.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7351a015770bb5ccfc6ff04a4b1397ea9f2a4bf11c6b87037eea67c83e361e2c"

  strings:
    $s1  = "while (pLBz < WPKI - (7775, 1935, 2)) {" fullword ascii
    $s2  = "oXz = NavB - QUeAL;" fullword ascii
    $s3  = "QUeAL = oXz * NavB;" fullword ascii
    $s4  = "return UQqytzBR + LBVjrtN + RjXDEB + ZJDwl + qgxGEQ + fHR;" fullword ascii
    $s5  = "function qWZ(LLLjPV, COMWQYsl) {" fullword ascii
    $s6  = "function Mne(SQtclwu, CoV) {" fullword ascii
    $s7  = "if (6 === false) {" fullword ascii
    $s8  = "if (4 === false) {" fullword ascii
    $s9  = "if (2 == true) {" fullword ascii
    $s10 = "if (4 == true) {" fullword ascii
    $s11 = "if (7 === true) {" fullword ascii
    $s12 = "function SEXvkU() {" fullword ascii
    $s13 = "switch (9) {" fullword ascii
    $s14 = "function gNnV(dfegg) {" fullword ascii
    $s15 = "NavB = MMAhNG / QUeAL;" fullword ascii
    $s16 = "return EIzHS;" fullword ascii
    $s17 = "return pLvEV;" fullword ascii
    $s18 = "function YePR(VzUVzMqe, ztuHkX) {" fullword ascii
    $s19 = "return ctZ;" fullword ascii
    $s20 = "var VvNb = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}