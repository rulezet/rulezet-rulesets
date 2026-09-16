rule PEiD_00394_COMPACK_v4_5__2__ {
  meta:
    description = "[COMPACK v4.5 (2)]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? E8 ?? ?? 5D 83 ?? ?? 55 50 53 51 52 0E 07 0E 1F 8B CE }

  condition:
    $a
}