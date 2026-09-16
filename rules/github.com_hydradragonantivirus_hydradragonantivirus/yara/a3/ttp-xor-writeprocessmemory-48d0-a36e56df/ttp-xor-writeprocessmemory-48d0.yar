rule TTP_XOR_WriteProcessMemory_48d0 {
  strings:
    $key_48d0 = { 1f a2 [2] 2d 80 [2] 2b b5 [2] 05 b5 [2] 3a a9 }

  condition:
    any of them
}