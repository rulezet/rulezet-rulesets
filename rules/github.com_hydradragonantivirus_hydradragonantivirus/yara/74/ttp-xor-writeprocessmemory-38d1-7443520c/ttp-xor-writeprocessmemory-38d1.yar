rule TTP_XOR_WriteProcessMemory_38d1 {
  strings:
    $key_38d1 = { 6f a3 [2] 5d 81 [2] 5b b4 [2] 75 b4 [2] 4a a8 }

  condition:
    any of them
}