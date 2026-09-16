rule TTP_XOR_WriteProcessMemory_2572 {
  strings:
    $key_2572 = { 72 00 [2] 40 22 [2] 46 17 [2] 68 17 [2] 57 0b }

  condition:
    any of them
}