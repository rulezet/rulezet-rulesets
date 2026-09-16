rule TTP_XOR_WriteProcessMemory_3cc5 {
  strings:
    $key_3cc5 = { 6b b7 [2] 59 95 [2] 5f a0 [2] 71 a0 [2] 4e bc }

  condition:
    any of them
}