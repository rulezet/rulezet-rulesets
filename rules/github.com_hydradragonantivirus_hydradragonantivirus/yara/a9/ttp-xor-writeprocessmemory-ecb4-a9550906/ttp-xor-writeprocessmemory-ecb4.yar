rule TTP_XOR_WriteProcessMemory_ecb4 {
  strings:
    $key_ecb4 = { bb c6 [2] 89 e4 [2] 8f d1 [2] a1 d1 [2] 9e cd }

  condition:
    any of them
}