rule TTP_XOR_WriteProcessMemory_88c2 {
  strings:
    $key_88c2 = { df b0 [2] ed 92 [2] eb a7 [2] c5 a7 [2] fa bb }

  condition:
    any of them
}