rule TTP_XOR_WriteProcessMemory_2657 {
  strings:
    $key_2657 = { 71 25 [2] 43 07 [2] 45 32 [2] 6b 32 [2] 54 2e }

  condition:
    any of them
}