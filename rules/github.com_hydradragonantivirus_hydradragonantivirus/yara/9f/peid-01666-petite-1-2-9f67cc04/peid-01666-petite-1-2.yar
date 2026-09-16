rule PEiD_01666_Petite_1_2_ {
  meta:
    description = "[Petite 1.2]"
    ep_only     = "true"

  strings:
    $a = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }

  condition:
    $a
}