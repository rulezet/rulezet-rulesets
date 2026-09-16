rule TTP_XOR_WriteProcessMemory_1962 {
  strings:
    $key_1962 = { 4e 10 [2] 7c 32 [2] 7a 07 [2] 54 07 [2] 6b 1b }

  condition:
    any of them
}