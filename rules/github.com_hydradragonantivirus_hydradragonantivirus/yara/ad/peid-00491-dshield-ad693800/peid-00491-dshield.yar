rule PEiD_00491_DSHIELD_ {
  meta:
    description = "[DSHIELD]"
    ep_only     = "true"

  strings:
    $a = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }

  condition:
    $a
}