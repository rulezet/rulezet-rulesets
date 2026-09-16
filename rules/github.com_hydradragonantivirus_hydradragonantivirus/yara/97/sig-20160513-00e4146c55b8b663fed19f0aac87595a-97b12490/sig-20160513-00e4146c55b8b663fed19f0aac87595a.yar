rule sig_20160513_00e4146c55b8b663fed19f0aac87595a {
  meta:
    description = "datamaliciousorder - file 20160513_00e4146c55b8b663fed19f0aac87595a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9594d4c843471608e96136fbe2fefec9dd726e22066b388882cbbe4a6c931a3b"

  strings:
    $s1  = "while (Gvhm < RlBqP - (4920 + 1368 - 6286)) {" fullword ascii
    $s2  = "function HayQf(MXaoWD, dCIa) {" fullword ascii
    $s3  = "return ULqHhU;" fullword ascii
    $s4  = "return Eqjz;" fullword ascii
    $s5  = "function BJF() {" fullword ascii
    $s6  = "function ISJiRjb(MpGznHNk, YnNH) {" fullword ascii
    $s7  = "return notysg;" fullword ascii
    $s8  = "function tTxUPgk(FNWw) {" fullword ascii
    $s9  = "return pMwI;" fullword ascii
    $s10 = "return fccdyQhK;" fullword ascii
    $s11 = "function KhQw(MVFJDQ, JzKWKpJ) {" fullword ascii
    $s12 = "return MycEt;" fullword ascii
    $s13 = "return rhBlUfNy;" fullword ascii
    $s14 = "function rRPkoo(Esd, QaYWuL) {" fullword ascii
    $s15 = "return TsOh;" fullword ascii
    $s16 = "ZxOV = true;" fullword ascii
    $s17 = "function tnnzysw() {" fullword ascii
    $s18 = "function EyXJB() {" fullword ascii
    $s19 = "function zYATmO() {" fullword ascii
    $s20 = "function lOy() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}