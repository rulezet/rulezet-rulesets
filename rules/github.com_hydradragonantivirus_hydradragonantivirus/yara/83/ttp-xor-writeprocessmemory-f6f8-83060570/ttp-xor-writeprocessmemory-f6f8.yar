rule TTP_XOR_WriteProcessMemory_f6f8 {
  strings:
    $key_f6f8 = { a1 8a [2] 93 a8 [2] 95 9d [2] bb 9d [2] 84 81 }

  condition:
    any of them
}