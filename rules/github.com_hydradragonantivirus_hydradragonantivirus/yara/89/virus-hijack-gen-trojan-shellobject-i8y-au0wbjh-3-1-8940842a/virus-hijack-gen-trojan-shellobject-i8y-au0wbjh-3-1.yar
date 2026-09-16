rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_au0WBJh_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@au0WBJh_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "150db9fc5759799e36fffc39207c73861b9a13373dcd28568314e13588550e11"

  strings:
    $s1  = "generational" fullword wide
    $s2  = "acrestaff" fullword wide
    $s3  = "PRESTIMULATE" fullword ascii
    $s4  = "ERYTHROPENIA" fullword ascii
    $s5  = "BARWAYS" fullword wide
    $s6  = "FAVORED" fullword wide
    $s7  = "SEMIYEARLY" fullword wide
    $s8  = "Indesignate" fullword ascii
    $s9  = "Honorably" fullword wide
    $s10 = "Submediant" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}