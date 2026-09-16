rule PEiD_01268_nbuild_v1_0__soft_ {
  meta:
    description = "[nbuild v1.0 [soft]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2 }

  condition:
    $a
}