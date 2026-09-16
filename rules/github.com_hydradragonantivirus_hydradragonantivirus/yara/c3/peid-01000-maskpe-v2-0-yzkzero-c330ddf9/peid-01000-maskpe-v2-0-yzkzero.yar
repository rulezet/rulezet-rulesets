rule PEiD_01000_MaskPE_V2_0____yzkzero_ {
  meta:
    description = "[MaskPE V2.0 -> yzkzero]"
    ep_only     = "false"

  strings:
    $a = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

  condition:
    $a
}