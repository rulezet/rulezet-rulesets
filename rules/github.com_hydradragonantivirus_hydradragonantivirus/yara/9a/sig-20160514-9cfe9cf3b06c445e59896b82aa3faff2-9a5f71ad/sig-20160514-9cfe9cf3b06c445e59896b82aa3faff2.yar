rule sig_20160514_9cfe9cf3b06c445e59896b82aa3faff2 {
  meta:
    description = "datamaliciousorder - file 20160514_9cfe9cf3b06c445e59896b82aa3faff2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f251d6e1052af2d6ddf58c0d309495e9035a80f4176f83df4910e59e9a9ded1"

  strings:
    $s1  = "while (biDuKE < qKIc - (9999 + 1277 - 11274)) {" fullword ascii
    $s2  = "return ZEYESO;" fullword ascii
    $s3  = "var lOOT = biDuKE + (2);" fullword ascii
    $s4  = "return LYRwv;" fullword ascii
    $s5  = "function ksshF() {" fullword ascii
    $s6  = "function EhJSA() {" fullword ascii
    $s7  = "return qLnpc;" fullword ascii
    $s8  = "function sdRp() {" fullword ascii
    $s9  = "return mfFqQWg;" fullword ascii
    $s10 = "function OFuEMG(MgjS) {" fullword ascii
    $s11 = "return sgLsRBH;" fullword ascii
    $s12 = "function FFr() {" fullword ascii
    $s13 = "return rECuGOUY;" fullword ascii
    $s14 = "return FnVGHCDG[QoRpXqMj];" fullword ascii
    $s15 = "function invixa(QoRpXqMj) {" fullword ascii
    $s16 = "return ZzKxERpR;" fullword ascii
    $s17 = "function oNPG(QueIJcZ, lBWsx) {" fullword ascii
    $s18 = "return jOzzib;" fullword ascii
    $s19 = "var aEQoBGw = String;" fullword ascii
    $s20 = "return GXmrkBuk;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}