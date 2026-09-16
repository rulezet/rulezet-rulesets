rule TTP_XOR_WriteProcessMemory_ecf3 {
  strings:
    $key_ecf3 = { bb 81 [2] 89 a3 [2] 8f 96 [2] a1 96 [2] 9e 8a }

  condition:
    any of them
}