rule VirusShareTrojanInject36111_9_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ca29325814427f5cb410364f0714da863cec087095a7b6d612c03afe02b5e3"

  strings:
    $s1 = "MaMo}|" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}