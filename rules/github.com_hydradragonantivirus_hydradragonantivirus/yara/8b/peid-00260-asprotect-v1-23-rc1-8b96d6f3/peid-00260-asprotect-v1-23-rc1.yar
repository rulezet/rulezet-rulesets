rule PEiD_00260_ASProtect_v1_23_RC1_ {
  meta:
    description = "[ASProtect v1.23 RC1]"
    ep_only     = "true"

  strings:
    $a = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }

  condition:
    $a
}