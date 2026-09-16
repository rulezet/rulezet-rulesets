rule TTP_XOR_WriteProcessMemory_4562 {
  strings:
    $key_4562 = { 12 10 [2] 20 32 [2] 26 07 [2] 08 07 [2] 37 1b }

  condition:
    any of them
}