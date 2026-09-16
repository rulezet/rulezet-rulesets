rule TTP_XOR_WriteProcessMemory_4362 {
  strings:
    $key_4362 = { 14 10 [2] 26 32 [2] 20 07 [2] 0e 07 [2] 31 1b }

  condition:
    any of them
}