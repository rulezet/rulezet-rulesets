rule PEiD_03488_WWPACK_v3_05c4__Modified__ {
  meta:
    description = "[WWPACK v3.05c4 (Modified)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

  condition:
    $a
}