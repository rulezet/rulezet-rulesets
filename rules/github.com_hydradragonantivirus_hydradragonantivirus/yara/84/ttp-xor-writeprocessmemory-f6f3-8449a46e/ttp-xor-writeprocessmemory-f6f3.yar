rule TTP_XOR_WriteProcessMemory_f6f3 {
  strings:
    $key_f6f3 = { a1 81 [2] 93 a3 [2] 95 96 [2] bb 96 [2] 84 8a }

  condition:
    any of them
}