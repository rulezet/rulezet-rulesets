rule TTP_XOR_WriteProcessMemory_18d0 {
  strings:
    $key_18d0 = { 4f a2 [2] 7d 80 [2] 7b b5 [2] 55 b5 [2] 6a a9 }

  condition:
    any of them
}