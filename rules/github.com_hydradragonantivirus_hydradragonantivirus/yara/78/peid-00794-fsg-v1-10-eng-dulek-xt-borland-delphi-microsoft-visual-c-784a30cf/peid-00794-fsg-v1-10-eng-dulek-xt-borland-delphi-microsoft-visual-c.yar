rule PEiD_00794_FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C____ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)]"
    ep_only     = "true"

  strings:
    $a = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

  condition:
    $a
}