rule PEiD_00511_Embed_PE_v1_13____cyclotron_ {
  meta:
    description = "[Embed PE v1.13 -> cyclotron]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }

  condition:
    $a
}