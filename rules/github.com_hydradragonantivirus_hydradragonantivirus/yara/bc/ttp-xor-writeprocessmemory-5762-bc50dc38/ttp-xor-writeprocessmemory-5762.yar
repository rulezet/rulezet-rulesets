rule TTP_XOR_WriteProcessMemory_5762 {
  strings:
    $key_5762 = { 00 10 [2] 32 32 [2] 34 07 [2] 1a 07 [2] 25 1b }

  condition:
    any of them
}