rule PEiD_00237_ASPack_v2_11d_ {
  meta:
    description = "[ASPack v2.11d]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 02 00 00 00 EB 09 5D 55 }

  condition:
    $a
}