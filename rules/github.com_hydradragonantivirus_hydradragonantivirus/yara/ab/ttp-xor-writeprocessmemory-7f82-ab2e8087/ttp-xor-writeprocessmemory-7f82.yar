rule TTP_XOR_WriteProcessMemory_7f82 {
  strings:
    $key_7f82 = { 28 f0 [2] 1a d2 [2] 1c e7 [2] 32 e7 [2] 0d fb }

  condition:
    any of them
}