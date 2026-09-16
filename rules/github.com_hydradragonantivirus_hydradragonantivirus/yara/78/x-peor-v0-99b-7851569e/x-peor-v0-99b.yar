import "pe"
rule X_PEOR_v0_99b {
  strings:
    $a0 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
    $a1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}