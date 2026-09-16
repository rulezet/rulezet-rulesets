rule sig_20160514_21cd91c761ed5bcb9c8fcc07d3c2a5f5 {
  meta:
    description = "datamaliciousorder - file 20160514_21cd91c761ed5bcb9c8fcc07d3c2a5f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "215156466ce7d65bb421bbb42d802d6765a07bae0f7539ce31f943fcacdc7f7e"

  strings:
    $s1  = "while (bIwEbop < WMMctHb - (3348 + 1221 - 4567)) {" fullword ascii
    $s2  = "return jucKVsy;" fullword ascii
    $s3  = "function SaiI() {" fullword ascii
    $s4  = "function LHQdZZL() {" fullword ascii
    $s5  = "return LMMCt;" fullword ascii
    $s6  = "return rGBWxVMx;" fullword ascii
    $s7  = "function JBN(RfvgT, HfZS) {" fullword ascii
    $s8  = "function jvqXnx() {" fullword ascii
    $s9  = "return wVHERuQ;" fullword ascii
    $s10 = "return mJyLD;" fullword ascii
    $s11 = "function SZYaPzS(euEucff, BOzqVXgs) {" fullword ascii
    $s12 = "function krfzcRE() {" fullword ascii
    $s13 = "function vLvDI(dfegg) {" fullword ascii
    $s14 = "return XNuP;" fullword ascii
    $s15 = "return oaEg;" fullword ascii
    $s16 = "function RIV() {" fullword ascii
    $s17 = "return jVYmcTpi;" fullword ascii
    $s18 = "return hWrkCd;" fullword ascii
    $s19 = "return QGfiaz;" fullword ascii
    $s20 = "function NlK() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}