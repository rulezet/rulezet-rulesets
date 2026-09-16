rule TTP_XOR_WriteProcessMemory_1cc5 {
  strings:
    $key_1cc5 = { 4b b7 [2] 79 95 [2] 7f a0 [2] 51 a0 [2] 6e bc }

  condition:
    any of them
}