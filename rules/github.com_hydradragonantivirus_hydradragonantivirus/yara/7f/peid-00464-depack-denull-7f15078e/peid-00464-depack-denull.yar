rule PEiD_00464_dePACK____deNULL_ {
  meta:
    description = "[dePACK -> deNULL]"
    ep_only     = "true"

  strings:
    $a = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00 }

  condition:
    $a
}