rule TTP_XOR_WriteProcessMemory_3362 {
  strings:
    $key_3362 = { 64 10 [2] 56 32 [2] 50 07 [2] 7e 07 [2] 41 1b }

  condition:
    any of them
}