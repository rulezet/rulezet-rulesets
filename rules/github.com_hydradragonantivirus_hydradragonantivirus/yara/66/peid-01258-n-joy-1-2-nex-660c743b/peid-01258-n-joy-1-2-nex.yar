rule PEiD_01258_N_Joy_1_2____NEX_ {
  meta:
    description = "[N-Joy 1.2 -> NEX]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }

  condition:
    $a
}