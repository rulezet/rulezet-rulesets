import "pe"
rule FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___4_x___LCC_Win32_1_x_ {
  strings:
    $a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

  condition:
    $a0 at pe.entry_point
}