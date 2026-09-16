rule TTP_XOR_WriteProcessMemory_1562 {
  strings:
    $key_1562 = { 42 10 [2] 70 32 [2] 76 07 [2] 58 07 [2] 67 1b }

  condition:
    any of them
}