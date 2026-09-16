rule TTP_XOR_WriteProcessMemory_f6f0 {
  strings:
    $key_f6f0 = { a1 82 [2] 93 a0 [2] 95 95 [2] bb 95 [2] 84 89 }

  condition:
    any of them
}