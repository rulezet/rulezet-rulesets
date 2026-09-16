import "pe"
rule __Six_to_Four__v1_0 {
  strings:
    $a0 = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED }

  condition:
    $a0 at pe.entry_point
}