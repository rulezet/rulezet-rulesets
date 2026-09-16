rule PEiD_00518_EmbedPE_V1_X____cyclotron_ {
  meta:
    description = "[EmbedPE V1.X -> cyclotron]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00 }

  condition:
    $a
}