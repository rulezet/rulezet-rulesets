rule PEiD_00111_ARJ_SFX_Custom_ {
  meta:
    description = "[ARJ SFX Custom]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 66 9C 60 50 8D 90 5C 01 00 00 68 00 00 40 00 83 3A 00 0F 84 C6 C1 FF FF 8B 04 24 8B 0A 0F BA F1 1F 73 13 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB D9 83 C2 10 8B 5A }

  condition:
    $a
}