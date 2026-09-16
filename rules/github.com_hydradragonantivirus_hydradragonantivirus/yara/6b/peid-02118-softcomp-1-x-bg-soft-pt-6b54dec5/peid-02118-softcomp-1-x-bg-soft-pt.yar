rule PEiD_02118_SoftComp_1_x____BG_Soft_PT_ {
  meta:
    description = "[SoftComp 1.x -> BG Soft PT]"
    ep_only     = "false"

  strings:
    $a = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }

  condition:
    $a
}