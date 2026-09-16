rule TTP_XOR_WriteProcessMemory_ecf7 {
  strings:
    $key_ecf7 = { bb 85 [2] 89 a7 [2] 8f 92 [2] a1 92 [2] 9e 8e }

  condition:
    any of them
}