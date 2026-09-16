rule sig_20160514_caf882db3ba92f00ad2353146a3e26eb {
  meta:
    description = "datamaliciousorder - file 20160514_caf882db3ba92f00ad2353146a3e26eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a53efe72ead03a46e14a3d911704268fbba7165b571feb1aea77f43d3a6645dd"

  strings:
    $s1  = "while (wYWdL < TrcInZy - (5794 - 5792)) {" fullword ascii
    $s2  = "function DglYrAt(dfegg) {" fullword ascii
    $s3  = "return UQQXzz;" fullword ascii
    $s4  = "return bzKAtO;" fullword ascii
    $s5  = "return FoCY;" fullword ascii
    $s6  = "return SCtws;" fullword ascii
    $s7  = "function CwygpNZ() {" fullword ascii
    $s8  = "function pTHyufP() {" fullword ascii
    $s9  = "function EQpWnhl(LXM) {" fullword ascii
    $s10 = "return VWHtQs;" fullword ascii
    $s11 = "function Jxc(Zncbr, wvqzj) {" fullword ascii
    $s12 = "function kpMQL() {" fullword ascii
    $s13 = "function KbhZF() {" fullword ascii
    $s14 = "return EqOEga;" fullword ascii
    $s15 = "switch (Dzdv) {" fullword ascii
    $s16 = "return uuZDdRS;" fullword ascii
    $s17 = "return NgrLPx;" fullword ascii
    $s18 = "return OaaierH;" fullword ascii
    $s19 = "return wyAwoTcw;" fullword ascii
    $s20 = "return csGH;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}