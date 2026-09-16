rule PEiD_02279_Thinstall_vx_x_ {
  meta:
    description = "[Thinstall vx.x]"
    ep_only     = "true"

  strings:
    $a = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

  condition:
    $a
}