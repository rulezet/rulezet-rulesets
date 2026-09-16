rule PEiD_00787_FSG_v1_10__Eng_____dulek_xt_____Borland_C____ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland C++)]"
    ep_only     = "true"

  strings:
    $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }

  condition:
    $a
}