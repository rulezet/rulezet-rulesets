import "pe"
rule PE_Crypt32_v1_02 {
  strings:
    $a0 = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }

  condition:
    $a0 at pe.entry_point
}