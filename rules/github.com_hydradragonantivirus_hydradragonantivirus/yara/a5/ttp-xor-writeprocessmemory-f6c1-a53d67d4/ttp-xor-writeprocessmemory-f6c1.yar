rule TTP_XOR_WriteProcessMemory_f6c1 {
  strings:
    $key_f6c1 = { a1 b3 [2] 93 91 [2] 95 a4 [2] bb a4 [2] 84 b8 }

  condition:
    any of them
}