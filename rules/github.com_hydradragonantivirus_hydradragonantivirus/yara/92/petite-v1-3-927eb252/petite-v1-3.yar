import "pe"
rule PEtite_v1_3 {
  strings:
    $a0 = { 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }

  condition:
    $a0 at pe.entry_point
}