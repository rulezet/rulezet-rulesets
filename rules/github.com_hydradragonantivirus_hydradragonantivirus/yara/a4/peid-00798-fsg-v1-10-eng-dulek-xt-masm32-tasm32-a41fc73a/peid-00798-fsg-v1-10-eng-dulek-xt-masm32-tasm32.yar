rule PEiD_00798_FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32)]"
    ep_only     = "true"

  strings:
    $a = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }

  condition:
    $a
}