rule PEiD_02348_Unpacked_BS_SFX_Archive_v1_9_ {
  meta:
    description = "[Unpacked BS-SFX Archive v1.9]"
    ep_only     = "true"

  strings:
    $a = { 1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73 }

  condition:
    $a
}