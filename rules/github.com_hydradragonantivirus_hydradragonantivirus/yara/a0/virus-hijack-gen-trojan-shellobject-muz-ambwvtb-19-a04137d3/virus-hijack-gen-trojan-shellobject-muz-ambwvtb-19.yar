rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e8079248a42e14afb528fd4199da1e36e3d9b4bced9b6bf7b7de898e34bf4"

  strings:
    $s1 = "S[lAsH*E," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}