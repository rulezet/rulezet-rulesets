rule PEiD_00803_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___4_x___LCC_Win32_1_x__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 4.x / LCC Win32 1.x)]"
    ep_only     = "true"

  strings:
    $a = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

  condition:
    $a
}