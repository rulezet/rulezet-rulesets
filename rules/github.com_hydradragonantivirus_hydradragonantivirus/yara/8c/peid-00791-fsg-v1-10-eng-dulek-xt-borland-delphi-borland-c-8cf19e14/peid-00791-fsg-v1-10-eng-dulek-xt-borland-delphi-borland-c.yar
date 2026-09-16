rule PEiD_00791_FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Borland_C____ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)]"
    ep_only     = "true"

  strings:
    $a = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

  condition:
    $a
}