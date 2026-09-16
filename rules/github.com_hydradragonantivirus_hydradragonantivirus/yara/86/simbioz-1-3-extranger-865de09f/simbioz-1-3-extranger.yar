import "pe"
rule SimbiOZ_1_3____Extranger {
  strings:
    $a0 = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }

  condition:
    $a0 at pe.entry_point
}