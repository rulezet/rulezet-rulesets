rule TTP_XOR_WriteProcessMemory_8497 {
  strings:
    $key_8497 = { d3 e5 [2] e1 c7 [2] e7 f2 [2] c9 f2 [2] f6 ee }

  condition:
    any of them
}