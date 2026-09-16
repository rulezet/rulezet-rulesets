rule TTP_XOR_WriteProcessMemory_78d1 {
  strings:
    $key_78d1 = { 2f a3 [2] 1d 81 [2] 1b b4 [2] 35 b4 [2] 0a a8 }

  condition:
    any of them
}