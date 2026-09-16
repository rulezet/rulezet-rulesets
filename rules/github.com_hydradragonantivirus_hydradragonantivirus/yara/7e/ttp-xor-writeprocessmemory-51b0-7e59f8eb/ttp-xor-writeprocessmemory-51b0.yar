rule TTP_XOR_WriteProcessMemory_51b0 {
  strings:
    $key_51b0 = { 06 c2 [2] 34 e0 [2] 32 d5 [2] 1c d5 [2] 23 c9 }

  condition:
    any of them
}