rule sig_20160516_7e358bc443211947858f3f2dd76b04f9 {
  meta:
    description = "datamaliciousorder - file 20160516_7e358bc443211947858f3f2dd76b04f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f6dee4d4831fb28a0aa99098028ff822637593ebac45257ab792e678bafd4e3"

  strings:
    $s1  = "while (MYpFh < EKydvXw - (5274 - 5272)) {" fullword ascii
    $s2  = "function RLZk(pwmYdA) {" fullword ascii
    $s3  = "function MXyXGA(TVtsh) {" fullword ascii
    $s4  = "function jSHhD(dfegg) {" fullword ascii
    $s5  = "return RtZx;" fullword ascii
    $s6  = "return BYXTjcoI;" fullword ascii
    $s7  = "return cuiiSz;" fullword ascii
    $s8  = "return dHybdnZv;" fullword ascii
    $s9  = "function xMrtM() {" fullword ascii
    $s10 = "function Kguni(nWKhwQ, nRrH) {" fullword ascii
    $s11 = "return Jxtzb;" fullword ascii
    $s12 = "function PnLLo(Rbi) {" fullword ascii
    $s13 = "return UFwMycWZ[Rbi];" fullword ascii
    $s14 = "function Arhyjl() {" fullword ascii
    $s15 = "return NpRWNDI;" fullword ascii
    $s16 = "return DylP;" fullword ascii
    $s17 = "function jFfx() {" fullword ascii
    $s18 = "return PfvoCqr;" fullword ascii
    $s19 = "function MiYRWV() {" fullword ascii
    $s20 = "return lRJHTtsP;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}