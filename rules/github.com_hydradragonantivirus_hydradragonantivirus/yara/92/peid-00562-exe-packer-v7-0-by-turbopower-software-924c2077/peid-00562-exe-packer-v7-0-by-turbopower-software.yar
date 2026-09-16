rule PEiD_00562_EXE_Packer_v7_0_by_TurboPower_Software_ {
  meta:
    description = "[EXE Packer v7.0 by TurboPower Software]"
    ep_only     = "true"

  strings:
    $a = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }

  condition:
    $a
}