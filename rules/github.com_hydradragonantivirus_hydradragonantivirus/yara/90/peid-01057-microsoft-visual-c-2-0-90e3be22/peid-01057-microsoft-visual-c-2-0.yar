rule PEiD_01057_Microsoft_Visual_C_2_0_ {
  meta:
    description = "[Microsoft Visual C 2.0]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 }

  condition:
    $a
}