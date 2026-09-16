rule PEiD_02114_Soft_Defender_1_1x____Randy_Li_ {
  meta:
    description = "[Soft Defender 1.1x -> Randy Li]"
    ep_only     = "true"

  strings:
    $a = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }

  condition:
    $a
}