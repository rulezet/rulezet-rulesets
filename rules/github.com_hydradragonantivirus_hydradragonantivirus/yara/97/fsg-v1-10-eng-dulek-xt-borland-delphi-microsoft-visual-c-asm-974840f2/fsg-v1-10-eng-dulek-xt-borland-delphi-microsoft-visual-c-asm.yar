import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Microsoft_Visual_C_____ASM_ {
  strings:
    $a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

  condition:
    $a0 at pe.entry_point
}