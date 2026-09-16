rule PEiD_01047_Microsoft_CAB_SFX_ {
  meta:
    description = "[Microsoft CAB SFX]"
    ep_only     = "true"

  strings:
    $a = { E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC }

  condition:
    $a
}