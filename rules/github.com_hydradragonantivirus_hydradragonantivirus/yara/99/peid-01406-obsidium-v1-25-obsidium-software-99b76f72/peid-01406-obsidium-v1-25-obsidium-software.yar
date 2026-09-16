rule PEiD_01406_Obsidium_V1_25____Obsidium_Software_ {
  meta:
    description = "[Obsidium V1.25 -> Obsidium Software]"
    ep_only     = "true"

  strings:
    $a = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }

  condition:
    $a
}