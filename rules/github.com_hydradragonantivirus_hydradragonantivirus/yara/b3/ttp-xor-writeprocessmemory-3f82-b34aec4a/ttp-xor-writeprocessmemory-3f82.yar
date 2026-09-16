rule TTP_XOR_WriteProcessMemory_3f82 {
  strings:
    $key_3f82 = { 68 f0 [2] 5a d2 [2] 5c e7 [2] 72 e7 [2] 4d fb }

  condition:
    any of them
}