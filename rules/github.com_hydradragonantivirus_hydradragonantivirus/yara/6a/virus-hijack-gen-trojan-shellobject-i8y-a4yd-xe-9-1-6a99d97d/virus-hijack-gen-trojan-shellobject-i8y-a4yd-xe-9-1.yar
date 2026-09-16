rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_a4YD_Xe_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45340047ec2f2142546bae056a0670f5f57451e18a91861ffab1b860b4e7c82d"

  strings:
    $s1  = "4&#;$#9* G/-H*+L5(aFFY<:R==P8>RD=I825'" fullword ascii
    $s2  = "  ilia@valley.ru" fullword ascii
    $s3  = "Action(=C" fullword ascii
    $s4  = "wZTXA<G/#T:0`EAcH@" fullword ascii
    $s5  = "[DEPA>F/,J;1N>5H?7WG;K=7N:3YFB_HC_IAZ@GW:?C1( " fullword ascii
    $s6  = "tidE;hHJ" fullword ascii
    $s7  = "da{SMoG?gG9U3.[<8`@8" fullword ascii
    $s8  = "lcQ>5@/\"@0(P88hXP`PLaK@cJHXH@pXPhTH" fullword ascii
    $s9  = "`@BX88`H@dIER;45" fullword ascii
    $s10 = "TArO@u" fullword ascii
    $s11 = "SARK<A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}