rule PEiD_00363_CAN2EXE_v0_01_ {
  meta:
    description = "[CAN2EXE v0.01]"
    ep_only     = "true"

  strings:
    $a = { 26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9 }

  condition:
    $a
}