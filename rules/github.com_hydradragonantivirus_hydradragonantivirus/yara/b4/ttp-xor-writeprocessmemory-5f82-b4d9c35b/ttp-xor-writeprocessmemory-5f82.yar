rule TTP_XOR_WriteProcessMemory_5f82 {
  strings:
    $key_5f82 = { 08 f0 [2] 3a d2 [2] 3c e7 [2] 12 e7 [2] 2d fb }

  condition:
    any of them
}