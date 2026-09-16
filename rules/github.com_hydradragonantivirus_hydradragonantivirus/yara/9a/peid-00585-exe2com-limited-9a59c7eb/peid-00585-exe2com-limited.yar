rule PEiD_00585_EXE2COM__Limited__ {
  meta:
    description = "[EXE2COM (Limited)]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20 }

  condition:
    $a
}