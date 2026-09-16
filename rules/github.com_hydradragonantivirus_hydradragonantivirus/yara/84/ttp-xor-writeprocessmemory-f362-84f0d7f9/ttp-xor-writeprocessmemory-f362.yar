rule TTP_XOR_WriteProcessMemory_f362 {
  strings:
    $key_f362 = { a4 10 [2] 96 32 [2] 90 07 [2] be 07 [2] 81 1b }

  condition:
    any of them
}