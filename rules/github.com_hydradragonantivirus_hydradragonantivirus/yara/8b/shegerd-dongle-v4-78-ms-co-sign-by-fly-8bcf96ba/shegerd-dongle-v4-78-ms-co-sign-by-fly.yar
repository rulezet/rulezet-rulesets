import "pe"
rule Shegerd_Dongle_V4_78____MS_Co______Sign_By_fly {
  strings:
    $a0 = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

  condition:
    $a0 at pe.entry_point
}