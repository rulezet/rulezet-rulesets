rule TTP_XOR_WriteProcessMemory_63a4 {
  strings:
    $key_63a4 = { 34 d6 [2] 06 f4 [2] 00 c1 [2] 2e c1 [2] 11 dd }

  condition:
    any of them
}