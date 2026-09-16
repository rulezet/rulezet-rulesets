rule PEiD_00238_ASPack_v2_12_ {
  meta:
    description = "[ASPack v2.12]"
    ep_only     = "false"

  strings:
    $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

  condition:
    $a
}