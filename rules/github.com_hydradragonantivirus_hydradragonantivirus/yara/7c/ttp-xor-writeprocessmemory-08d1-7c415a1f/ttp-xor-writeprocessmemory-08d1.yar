rule TTP_XOR_WriteProcessMemory_08d1 {
  strings:
    $key_08d1 = { 5f a3 [2] 6d 81 [2] 6b b4 [2] 45 b4 [2] 7a a8 }

  condition:
    any of them
}