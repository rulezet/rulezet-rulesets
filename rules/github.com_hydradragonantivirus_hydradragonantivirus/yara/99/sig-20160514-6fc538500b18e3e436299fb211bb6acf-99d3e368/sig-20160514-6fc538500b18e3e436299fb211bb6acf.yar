rule sig_20160514_6fc538500b18e3e436299fb211bb6acf {
  meta:
    description = "datamaliciousorder - file 20160514_6fc538500b18e3e436299fb211bb6acf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b06cbf3010e2e23f843723b1a6f7161f7e2eaec4afbdb7fca6ab0b80c132f40"

  strings:
    $s1  = "while (BjLZlMZf < GufNJ - (3727 - 3725)) {" fullword ascii
    $s2  = "function RhcifH(ULXkjr) {" fullword ascii
    $s3  = "function YEwt(UDN, dJeo) {" fullword ascii
    $s4  = "function wSNxZ(KtA) {" fullword ascii
    $s5  = "function SFwZqSy() {" fullword ascii
    $s6  = "return jwfkCQHk[lZSGhBYg];" fullword ascii
    $s7  = "switch (523) {" fullword ascii
    $s8  = "return fWVQuG;" fullword ascii
    $s9  = "function TmR(lZSGhBYg) {" fullword ascii
    $s10 = "return qxGdDCL;" fullword ascii
    $s11 = "return SaQqRo;" fullword ascii
    $s12 = "function uzqdlU() {" fullword ascii
    $s13 = "function pALZk() {" fullword ascii
    $s14 = "return BSOB;" fullword ascii
    $s15 = "return ieGPaQe;" fullword ascii
    $s16 = "function kuACLv(hQcVv) {" fullword ascii
    $s17 = "return YHVjoh;" fullword ascii
    $s18 = "function woTYVoy(tuiyo, fmmd, kemn) {" fullword ascii
    $s19 = "function vyqEmB() {" fullword ascii
    $s20 = "function DuZWB() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}