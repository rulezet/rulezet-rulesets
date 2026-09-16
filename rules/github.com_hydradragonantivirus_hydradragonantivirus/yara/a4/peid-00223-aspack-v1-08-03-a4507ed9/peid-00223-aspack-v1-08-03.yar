rule PEiD_00223_ASPack_v1_08_03_ {
  meta:
    description = "[ASPack v1.08.03]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }

  condition:
    $a
}