rule PEiD_01957_Reg2Exe_2_25___by_Jan_Vorel_ {
  meta:
    description = "[Reg2Exe 2.25 - by Jan Vorel]"
    ep_only     = "true"

  strings:
    $a = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 }

  condition:
    $a
}