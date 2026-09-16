rule PEiD_01449_Packman_V1_0____Brandon_LaCombe_ {
  meta:
    description = "[Packman V1.0 -> Brandon LaCombe]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

  condition:
    $a
}