import "pe"
rule _Virus_Hijack_Trojan_EmotetU_Gen_n00_h4Idvkbi_Virus_Hijack_Troja_149 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.EmotetU.Gen.n00@h4Idvkbi.vir, Virus.Hijack_Trojan.EmotetU.Gen.n00@hGYa7Xhi.vir, Virus.Hijack_Trojan.EmotetU.Gen.n00@hW4OdDai.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d82016454fa8449e50c455461a736c22bf37fac5cc7a84729219a3d736d00dbf"
    hash2       = "bbbf9a2004156a5d1031c7b7c3748cf0c245b95d0258ef3616ef82a4d6ce102f"
    hash3       = "c383a5ca79c3b4775aca7228e0aef64924420834fb305aa57fc1a5892744fb62"

  strings:
    $s1 = "incrimination" fullword wide
    $s2 = "unseemliness" fullword wide
    $s3 = "uncontestableness" fullword wide
    $s4 = "8,!deED @$``` " fullword ascii
    $s5 = "{]wali" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1c6c3b0bd56b7f130f1f283a88a358b9" and (all of them)
    ) or (all of them)
}