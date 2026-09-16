rule PEiD_00825_FSG_v1_10__Eng_____dulek_xt_ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt]"
    ep_only     = "true"

  strings:
    $a = { E8 01 00 00 00 ?? ?? E8 ?? 00 00 00 }

  condition:
    $a
}