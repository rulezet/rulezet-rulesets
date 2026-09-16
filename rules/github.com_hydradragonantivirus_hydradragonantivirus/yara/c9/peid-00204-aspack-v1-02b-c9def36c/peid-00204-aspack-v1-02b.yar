rule PEiD_00204_ASPack_v1_02b_ {
  meta:
    description = "[ASPack v1.02b]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }

  condition:
    $a
}