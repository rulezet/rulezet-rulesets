import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___ASM_ {
  strings:
    $a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }

  condition:
    $a0 at pe.entry_point
}