rule TTP_XOR_WriteProcessMemory_4dd1 {
  strings:
    $key_4dd1 = { 1a a3 [2] 28 81 [2] 2e b4 [2] 00 b4 [2] 3f a8 }

  condition:
    any of them
}