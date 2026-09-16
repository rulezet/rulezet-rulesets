import "pe"
rule WWPACK_v3_03 {
  strings:
    $a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }

  condition:
    $a0 at pe.entry_point
}