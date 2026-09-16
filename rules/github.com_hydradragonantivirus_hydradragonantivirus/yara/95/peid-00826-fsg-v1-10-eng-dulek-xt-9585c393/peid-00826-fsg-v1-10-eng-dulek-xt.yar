rule PEiD_00826_FSG_v1_10__Eng_____dulek_xt_ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt]"
    ep_only     = "true"

  strings:
    $a = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }

  condition:
    $a
}