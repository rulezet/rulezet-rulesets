rule PEiD_02131_Software_Compress_v1_4_LITE____BG_Software_Protect_Technologies__h__ {
  meta:
    description = "[Software Compress v1.4 LITE -> BG Software Protect Technologies (h)]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }

  condition:
    $a
}