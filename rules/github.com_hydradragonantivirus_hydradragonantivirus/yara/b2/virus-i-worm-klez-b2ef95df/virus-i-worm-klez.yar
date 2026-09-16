import "pe"
rule VIRUS___I_Worm_KLEZ {
  strings:
    $a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

  condition:
    $a0 at pe.entry_point
}