import "pe"
rule tElock09910privatetE {
  strings:
    $a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0 at (pe.entry_point)
}