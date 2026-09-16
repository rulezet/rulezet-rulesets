rule PEiD_00492_Dual_s_Cryptor____dual_ {
  meta:
    description = "[Dual's Cryptor -> dual]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E }

  condition:
    $a
}