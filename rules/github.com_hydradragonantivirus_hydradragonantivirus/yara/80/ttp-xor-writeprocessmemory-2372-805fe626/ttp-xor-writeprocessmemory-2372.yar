rule TTP_XOR_WriteProcessMemory_2372 {
  strings:
    $key_2372 = { 74 00 [2] 46 22 [2] 40 17 [2] 6e 17 [2] 51 0b }

  condition:
    any of them
}