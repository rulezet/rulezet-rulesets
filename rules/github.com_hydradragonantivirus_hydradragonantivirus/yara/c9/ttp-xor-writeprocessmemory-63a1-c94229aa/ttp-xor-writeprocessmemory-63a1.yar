rule TTP_XOR_WriteProcessMemory_63a1 {
  strings:
    $key_63a1 = { 34 d3 [2] 06 f1 [2] 00 c4 [2] 2e c4 [2] 11 d8 }

  condition:
    any of them
}