import "pe"
rule WWPACK_v3_02__v3_02a__Extractable_ {
  strings:
    $a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }

  condition:
    $a0 at pe.entry_point
}