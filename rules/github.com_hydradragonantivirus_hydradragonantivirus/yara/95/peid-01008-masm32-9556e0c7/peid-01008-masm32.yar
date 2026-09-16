rule PEiD_01008_MASM32_ {
  meta:
    description = "[MASM32]"
    ep_only     = "true"

  strings:
    $a = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

  condition:
    $a
}