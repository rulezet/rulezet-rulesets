rule Virus_Hijack_Gen_Trojan_ShellObject_suZ_aiy413e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.suZ@aiy413e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a539ebdb475333f02fef677f9562dc9d494cdda6fe2a458c8e28cfd7def707d5"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}