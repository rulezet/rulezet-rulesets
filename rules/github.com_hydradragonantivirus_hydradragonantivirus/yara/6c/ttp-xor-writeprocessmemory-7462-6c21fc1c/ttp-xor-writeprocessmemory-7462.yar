rule TTP_XOR_WriteProcessMemory_7462 {
  strings:
    $key_7462 = { 23 10 [2] 11 32 [2] 17 07 [2] 39 07 [2] 06 1b }

  condition:
    any of them
}