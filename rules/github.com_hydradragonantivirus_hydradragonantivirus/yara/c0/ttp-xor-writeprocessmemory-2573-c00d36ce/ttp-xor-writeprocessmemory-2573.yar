rule TTP_XOR_WriteProcessMemory_2573 {
  strings:
    $key_2573 = { 72 01 [2] 40 23 [2] 46 16 [2] 68 16 [2] 57 0a }

  condition:
    any of them
}