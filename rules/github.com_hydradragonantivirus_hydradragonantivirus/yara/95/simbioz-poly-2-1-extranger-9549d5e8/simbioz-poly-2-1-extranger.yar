import "pe"
rule SimbiOZ_Poly_2_1____Extranger {
  strings:
    $a0 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }

  condition:
    $a0 at pe.entry_point
}