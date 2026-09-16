rule PEiD_03387_Vx__Grazie_883_ {
  meta:
    description = "[Vx: Grazie.883]"
    ep_only     = "true"

  strings:
    $a = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21 }

  condition:
    $a
}