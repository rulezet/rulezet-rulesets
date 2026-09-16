rule TTP_XOR_WriteProcessMemory_51a0 {
  strings:
    $key_51a0 = { 06 d2 [2] 34 f0 [2] 32 c5 [2] 1c c5 [2] 23 d9 }

  condition:
    any of them
}