rule PEiD_03483_WWPACK_v3_03_ {
  meta:
    description = "[WWPACK v3.03]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }

  condition:
    $a
}