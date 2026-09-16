rule PEiD_00783_FSG_v1_10__Eng_____bart_xt____WinRAR_SFX_ {
  meta:
    description = "[FSG v1.10 (Eng) -> bart/xt -> WinRAR-SFX]"
    ep_only     = "true"

  strings:
    $a = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }

  condition:
    $a
}