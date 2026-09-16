rule PEiD_01675_Petite_2_2_____c_1998_99_Ian_Luck_ {
  meta:
    description = "[Petite 2.2 -> (c)1998-99 Ian Luck]"
    ep_only     = "true"

  strings:
    $a = { ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 }

  condition:
    $a
}