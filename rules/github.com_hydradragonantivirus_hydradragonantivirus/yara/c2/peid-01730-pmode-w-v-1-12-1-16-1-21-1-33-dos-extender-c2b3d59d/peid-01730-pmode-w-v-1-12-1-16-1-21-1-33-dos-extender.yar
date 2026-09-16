rule PEiD_01730_PMODE_W_v_1_12__1_16__1_21__1_33_DOS_extender_ {
  meta:
    description = "[PMODE/W v.1.12, 1.16, 1.21, 1.33 DOS extender]"
    ep_only     = "true"

  strings:
    $a = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }

  condition:
    $a
}