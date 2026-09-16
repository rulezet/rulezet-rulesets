rule PEiD_00512_EmbedPE_1_13____cyclotron_ {
  meta:
    description = "[EmbedPE 1.13 -> cyclotron]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 }

  condition:
    $a
}