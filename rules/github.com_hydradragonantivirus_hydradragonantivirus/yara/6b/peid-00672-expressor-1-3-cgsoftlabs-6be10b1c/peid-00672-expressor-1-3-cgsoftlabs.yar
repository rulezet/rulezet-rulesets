rule PEiD_00672_eXPressor_1_3____CGSoftLabs_ {
  meta:
    description = "[eXPressor 1.3 -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E }

  condition:
    $a
}