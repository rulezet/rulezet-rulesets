rule TTP_XOR_WriteProcessMemory_ecb2 {
  strings:
    $key_ecb2 = { bb c0 [2] 89 e2 [2] 8f d7 [2] a1 d7 [2] 9e cb }

  condition:
    any of them
}