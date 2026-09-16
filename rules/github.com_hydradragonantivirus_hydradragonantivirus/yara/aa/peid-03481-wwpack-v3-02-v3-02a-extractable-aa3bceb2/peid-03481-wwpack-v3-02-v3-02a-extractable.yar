rule PEiD_03481_WWPACK_v3_02__v3_02a__Extractable__ {
  meta:
    description = "[WWPACK v3.02, v3.02a (Extractable)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }

  condition:
    $a
}