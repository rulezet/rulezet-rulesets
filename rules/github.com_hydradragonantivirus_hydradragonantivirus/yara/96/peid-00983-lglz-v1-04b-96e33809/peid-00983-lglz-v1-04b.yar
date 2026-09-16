rule PEiD_00983_LGLZ_v1_04b_ {
  meta:
    description = "[LGLZ v1.04b]"
    ep_only     = "true"

  strings:
    $a = { FC 1E 06 0E 8C C8 ?? ?? ?? ?? BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 ?? ?? F3 A5 4B 48 4A 79 }

  condition:
    $a
}