rule PEiD_00770_FSG_1_20__Eng_____dulek_xt_____Borland_C____ {
  meta:
    description = "[FSG 1.20 (Eng) -> dulek/xt -> (Borland C++)]"
    ep_only     = "false"

  strings:
    $a = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

  condition:
    $a
}