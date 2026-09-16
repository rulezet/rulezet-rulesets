rule PEiD_01001_MASM___TASM_ {
  meta:
    description = "[MASM / TASM]"
    ep_only     = "true"

  strings:
    $a = { 6A 00 E8 ?? 0? 00 00 A3 ?? 32 40 00 E8 ?? 0? 00 00 }

  condition:
    $a
}