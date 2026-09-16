import "pe"
rule _Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_16_2_V_292 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_16_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_23_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88bb9d0ecb52c0d5a024287caa7bdf03502ed536728988e6af7290399c873cb4"
    hash2       = "4518e39cae8a580d388d0a729d38235d6324d4db1c596ad3db06d661131924b6"
    hash3       = "cd778d0104c736ba30345dd9563b44ef91af6e67e220c82bce341148fd3a486a"

  strings:
    $s1  = " - Hostile NPC" fullword wide
    $s2  = " - Unexplored" fullword wide
    $s3  = " - Neutral NPC" fullword wide
    $s4  = " - Unactive Trap" fullword wide
    $s5  = " - Active Trap" fullword wide
    $s6  = "* You did nothing" fullword wide
    $s7  = "Hostile" fullword wide
    $s8  = " - Food" fullword wide
    $s9  = " - Weapon" fullword wide
    $s10 = " - Player" fullword wide
    $s11 = " - Exit" fullword wide
    $s12 = "You attacked a hostile NPC for " fullword wide
    $s13 = "+++++++++++++++++++++++++++ LP1 RogueLite : Level " fullword wide
    $s14 = ") but you are already full health" fullword wide
    $s15 = " damage and he became hostile" fullword wide
    $s16 = "You tried to drop a food (" fullword wide
    $s17 = "You droped a food (" fullword wide
    $s18 = ") Drop item" fullword wide
    $s19 = " just broke" fullword wide
    $s20 = "You tried to drop a weapon (" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}