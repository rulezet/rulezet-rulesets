rule TTP_XOR_WriteProcessMemory_51f0 {
  strings:
    $key_51f0 = { 06 82 [2] 34 a0 [2] 32 95 [2] 1c 95 [2] 23 89 }

  condition:
    any of them
}