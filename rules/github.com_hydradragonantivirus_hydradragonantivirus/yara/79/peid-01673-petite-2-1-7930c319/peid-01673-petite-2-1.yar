rule PEiD_01673_Petite_2_1_ {
  meta:
    description = "[Petite 2.1]"
    ep_only     = "false"

  strings:
    $a = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }

  condition:
    $a
}