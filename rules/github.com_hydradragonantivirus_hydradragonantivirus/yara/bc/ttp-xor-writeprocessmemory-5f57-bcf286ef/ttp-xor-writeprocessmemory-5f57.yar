rule TTP_XOR_WriteProcessMemory_5f57 {
  strings:
    $key_5f57 = { 08 25 [2] 3a 07 [2] 3c 32 [2] 12 32 [2] 2d 2e }

  condition:
    any of them
}