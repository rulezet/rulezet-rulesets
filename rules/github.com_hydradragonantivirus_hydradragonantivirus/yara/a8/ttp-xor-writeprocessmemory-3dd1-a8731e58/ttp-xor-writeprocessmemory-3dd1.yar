rule TTP_XOR_WriteProcessMemory_3dd1 {
  strings:
    $key_3dd1 = { 6a a3 [2] 58 81 [2] 5e b4 [2] 70 b4 [2] 4f a8 }

  condition:
    any of them
}