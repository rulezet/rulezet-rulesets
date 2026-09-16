rule PEiD_02071_Shrinker_3_2_ {
  meta:
    description = "[Shrinker 3.2]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }

  condition:
    $a
}