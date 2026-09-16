rule sig_20160428_fe2ab9484ac02caa1f67c62d0298dd7c {
  meta:
    description = "datamaliciousorder - file 20160428_fe2ab9484ac02caa1f67c62d0298dd7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de835aec7183e808192083f1e9c6b0f267c2099b17ca0cdc78142f2bad7bf20"

  strings:
    $s1  = "while (mCd < ahidaD - (3263, 4040, 7109, 85, 448, 2294, 2)) {" fullword ascii
    $s2  = "return eeJkiUS + sTQbuI + CQdTK + dvAvcDK + UyOZhYh + QKu;" fullword ascii
    $s3  = "if (6 === false) {" fullword ascii
    $s4  = "if (1 == false) {" fullword ascii
    $s5  = "if (5 === false) {" fullword ascii
    $s6  = "function CXiS(MLUbGjO) {" fullword ascii
    $s7  = "if (RCu == false) {" fullword ascii
    $s8  = "return jSTxKdV;" fullword ascii
    $s9  = "function ZNAZwI(mKDzgBq, PrzIJtd) {" fullword ascii
    $s10 = "function tYPs(lfdd, lgldr, kfkm) {" fullword ascii
    $s11 = "function eyQd(KmbI) {" fullword ascii
    $s12 = "return ihfCgUU;" fullword ascii
    $s13 = "var TFxxZ = false;;" fullword ascii
    $s14 = "if (isqRAp(0, true, false, 372) == false) {" fullword ascii
    $s15 = "var GxuSo = true;" fullword ascii
    $s16 = "var hmuuya = true;" fullword ascii
    $s17 = "return Xja;" fullword ascii
    $s18 = "function WkUC() {" fullword ascii
    $s19 = "if (wcLuECO === true) {" fullword ascii
    $s20 = "var quqqV = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}