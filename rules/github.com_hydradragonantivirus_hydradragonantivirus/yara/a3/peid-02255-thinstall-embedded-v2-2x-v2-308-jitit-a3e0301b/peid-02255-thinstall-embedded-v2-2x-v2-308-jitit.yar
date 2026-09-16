rule PEiD_02255_Thinstall_Embedded_V2_2X_V2_308____Jitit_ {
  meta:
    description = "[Thinstall Embedded V2.2X-V2.308 -> Jitit]"
    ep_only     = "true"

  strings:
    $a = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }

  condition:
    $a
}