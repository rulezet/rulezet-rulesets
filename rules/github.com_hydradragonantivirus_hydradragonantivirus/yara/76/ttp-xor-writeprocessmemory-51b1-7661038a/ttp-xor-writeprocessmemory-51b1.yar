rule TTP_XOR_WriteProcessMemory_51b1 {
  strings:
    $key_51b1 = { 06 c3 [2] 34 e1 [2] 32 d4 [2] 1c d4 [2] 23 c8 }

  condition:
    any of them
}