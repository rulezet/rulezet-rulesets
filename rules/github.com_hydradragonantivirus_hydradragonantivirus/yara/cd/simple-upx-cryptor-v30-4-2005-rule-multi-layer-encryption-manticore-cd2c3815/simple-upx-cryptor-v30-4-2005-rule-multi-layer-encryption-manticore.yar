import "pe"
rule Simple_UPX_Cryptor_v30_4_2005_rule__multi_layer_encryption______MANtiCORE {
  strings:
    $a0 = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
    $a1 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}