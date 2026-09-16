rule TTP_XOR_WriteProcessMemory_ecb0 {
  strings:
    $key_ecb0 = { bb c2 [2] 89 e0 [2] 8f d5 [2] a1 d5 [2] 9e c9 }

  condition:
    any of them
}