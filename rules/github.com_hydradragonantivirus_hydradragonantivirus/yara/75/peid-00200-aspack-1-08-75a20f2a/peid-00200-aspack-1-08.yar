rule PEiD_00200_ASPack_1_08_ {
  meta:
    description = "[ASPack 1.08]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 75 01 90 E9 }

  condition:
    $a
}