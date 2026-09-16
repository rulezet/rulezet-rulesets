rule TTP_XOR_WriteProcessMemory_f6c0 {
  strings:
    $key_f6c0 = { a1 b2 [2] 93 90 [2] 95 a5 [2] bb a5 [2] 84 b9 }

  condition:
    any of them
}