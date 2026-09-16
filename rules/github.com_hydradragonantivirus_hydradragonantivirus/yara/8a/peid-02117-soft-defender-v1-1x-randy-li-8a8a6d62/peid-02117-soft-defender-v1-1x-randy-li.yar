rule PEiD_02117_Soft_Defender_v1_1x____Randy_Li_ {
  meta:
    description = "[Soft Defender v1.1x -> Randy Li]"
    ep_only     = "true"

  strings:
    $a = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D }

  condition:
    $a
}