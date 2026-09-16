rule Virus_Hijack_Gen_Trojan_ShellObject_y8Z_aSSruKo_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.y8Z@aSSruKo_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6031d77ca30de6e4268b6c30cb893403c9161d756281572fafa9ec8f12e893c"

  strings:
    $s1 = "L{@cOlD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}