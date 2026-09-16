rule TTP_XOR_WriteProcessMemory_ecb6 {
  strings:
    $key_ecb6 = { bb c4 [2] 89 e6 [2] 8f d3 [2] a1 d3 [2] 9e cf }

  condition:
    any of them
}