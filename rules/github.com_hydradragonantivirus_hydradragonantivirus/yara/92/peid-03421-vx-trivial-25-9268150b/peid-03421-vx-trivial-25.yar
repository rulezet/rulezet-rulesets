rule PEiD_03421_Vx__Trivial_25_ {
  meta:
    description = "[Vx: Trivial.25]"
    ep_only     = "true"

  strings:
    $a = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }

  condition:
    $a
}