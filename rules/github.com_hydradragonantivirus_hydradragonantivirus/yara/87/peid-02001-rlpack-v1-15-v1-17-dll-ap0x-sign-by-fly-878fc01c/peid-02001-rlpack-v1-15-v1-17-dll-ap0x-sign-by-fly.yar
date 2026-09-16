rule PEiD_02001_RLPack_V1_15_V1_17_Dll____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLPack V1.15-V1.17 Dll -> ap0x ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }

  condition:
    $a
}