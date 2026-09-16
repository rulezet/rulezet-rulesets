rule PEiD_03406_Vx__Necropolis_1963_ {
  meta:
    description = "[Vx: Necropolis.1963]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0 }

  condition:
    $a
}