rule TTP_XOR_WriteProcessMemory_1862 {
  strings:
    $key_1862 = { 4f 10 [2] 7d 32 [2] 7b 07 [2] 55 07 [2] 6a 1b }

  condition:
    any of them
}