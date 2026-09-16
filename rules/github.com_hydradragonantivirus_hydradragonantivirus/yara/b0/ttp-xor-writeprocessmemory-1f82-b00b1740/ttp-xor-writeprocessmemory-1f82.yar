rule TTP_XOR_WriteProcessMemory_1f82 {
  strings:
    $key_1f82 = { 48 f0 [2] 7a d2 [2] 7c e7 [2] 52 e7 [2] 6d fb }

  condition:
    any of them
}