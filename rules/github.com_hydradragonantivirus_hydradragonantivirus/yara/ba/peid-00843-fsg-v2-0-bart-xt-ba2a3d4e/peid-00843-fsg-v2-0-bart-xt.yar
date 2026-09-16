rule PEiD_00843_FSG_v2_0____bart_xt_ {
  meta:
    description = "[FSG v2.0 -> bart/xt]"
    ep_only     = "true"

  strings:
    $a = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }

  condition:
    $a
}