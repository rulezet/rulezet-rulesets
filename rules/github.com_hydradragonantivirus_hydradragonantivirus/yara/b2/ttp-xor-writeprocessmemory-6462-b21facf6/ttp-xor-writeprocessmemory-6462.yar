rule TTP_XOR_WriteProcessMemory_6462 {
  strings:
    $key_6462 = { 33 10 [2] 01 32 [2] 07 07 [2] 29 07 [2] 16 1b }

  condition:
    any of them
}