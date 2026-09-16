import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_202_2_Tro_328 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_202_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df30923593bd46acc22ee150df173c4672161b66132af483d064ed6804d4db3f"
    hash2       = "c8e543607841185cc38e8b2c4150d4fa9d14bd54fbd2cd43cc256485aae62ef8"
    hash3       = "6d720c61d58149d861d0e12044fb93a56e159a45d9e876d60604aa135ca6f654"

  strings:
    $s1  = "Form1 - Integration" fullword wide
    $s2  = "<move>5__5" fullword ascii
    $s3  = "<move>5__6" fullword ascii
    $s4  = "<before>5__6" fullword ascii
    $s5  = "<found>5__8" fullword ascii
    $s6  = "<ship>5__5" fullword ascii
    $s7  = "<ship>5__4" fullword ascii
    $s8  = "Next move" fullword wide
    $s9  = "Generate game" fullword wide
    $s10 = "Run game" fullword wide
    $s11 = "Invalid move" fullword wide
    $s12 = "<vertical>5__2" fullword ascii
    $s13 = "<vertical>5__1" fullword ascii
    $s14 = "S&W Cafeteria" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}