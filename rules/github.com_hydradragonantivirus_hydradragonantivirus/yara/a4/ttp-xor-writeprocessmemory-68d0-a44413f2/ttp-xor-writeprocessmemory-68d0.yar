rule TTP_XOR_WriteProcessMemory_68d0 {
  strings:
    $key_68d0 = { 3f a2 [2] 0d 80 [2] 0b b5 [2] 25 b5 [2] 1a a9 }

  condition:
    any of them
}