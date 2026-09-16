rule TTP_XOR_WriteProcessMemory_f6d1 {
  strings:
    $key_f6d1 = { a1 a3 [2] 93 81 [2] 95 b4 [2] bb b4 [2] 84 a8 }

  condition:
    any of them
}