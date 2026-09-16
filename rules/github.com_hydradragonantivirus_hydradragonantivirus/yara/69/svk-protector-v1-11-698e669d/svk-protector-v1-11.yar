import "pe"
rule SVK_Protector_v1_11 {
  strings:
    $a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }

  condition:
    $a0 at pe.entry_point
}