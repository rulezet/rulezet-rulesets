rule sig_20160514_1a7b5d58cddd94daaf29a843c89da60e {
  meta:
    description = "datamaliciousorder - file 20160514_1a7b5d58cddd94daaf29a843c89da60e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e00de374551df56c5fb0208d83d7e75ffe92d8906197a28220872c4e6d7086e3"

  strings:
    $s1  = "while (EIpb < jZglPL - (8839 - 8837)) {" fullword ascii
    $s2  = "return BDPmjM[fgPbHx];" fullword ascii
    $s3  = "function HecK() {" fullword ascii
    $s4  = "QEipC = true;" fullword ascii
    $s5  = "return pNqQ;" fullword ascii
    $s6  = "function HWz(fgPbHx) {" fullword ascii
    $s7  = "function efAPFlv() {" fullword ascii
    $s8  = "function SqqIdd(RsvJiePv, vLXEcjl) {" fullword ascii
    $s9  = "return VzLHDKQj;" fullword ascii
    $s10 = "function ipRR() {" fullword ascii
    $s11 = "return sBIK;" fullword ascii
    $s12 = "return pEJtK;" fullword ascii
    $s13 = "function RNJgF() {" fullword ascii
    $s14 = "return PTOOYPm;" fullword ascii
    $s15 = "function hyTQ() {" fullword ascii
    $s16 = "function vETvTU(lIqAw) {" fullword ascii
    $s17 = "function OeIQM() {" fullword ascii
    $s18 = "function vvWRatL() {" fullword ascii
    $s19 = "return YOkntTHd;" fullword ascii
    $s20 = "return KxEsB;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}