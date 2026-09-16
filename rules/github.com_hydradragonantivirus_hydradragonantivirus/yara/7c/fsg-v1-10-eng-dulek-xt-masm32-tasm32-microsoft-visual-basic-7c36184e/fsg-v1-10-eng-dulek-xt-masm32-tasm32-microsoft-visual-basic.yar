import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____MASM32___TASM32___Microsoft_Visual_Basic_ {
  strings:
    $a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

  condition:
    $a0 at pe.entry_point
}