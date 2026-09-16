rule PEiD_01003_MASM___TASM_ {
  meta:
    description = "[MASM / TASM]"
    ep_only     = "false"

  strings:
    $a = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }

  condition:
    $a
}