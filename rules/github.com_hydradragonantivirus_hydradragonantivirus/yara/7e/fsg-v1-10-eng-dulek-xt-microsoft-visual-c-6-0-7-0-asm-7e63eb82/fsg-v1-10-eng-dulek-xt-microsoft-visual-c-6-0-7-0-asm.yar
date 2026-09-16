import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0___ASM_ {
  strings:
    $a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }

  condition:
    $a0 at pe.entry_point
}