import "pe"
rule WWPACK_v3_00__v3_01__Extractable_ {
  strings:
    $a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }

  condition:
    $a0 at pe.entry_point
}