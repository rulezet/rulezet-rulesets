rule TTP_XOR_WriteProcessMemory_5f62 {
  strings:
    $key_5f62 = { 08 10 [2] 3a 32 [2] 3c 07 [2] 12 07 [2] 2d 1b }

  condition:
    any of them
}