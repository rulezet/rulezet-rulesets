rule TTP_XOR_WriteProcessMemory_ecf0 {
  strings:
    $key_ecf0 = { bb 82 [2] 89 a0 [2] 8f 95 [2] a1 95 [2] 9e 89 }

  condition:
    any of them
}