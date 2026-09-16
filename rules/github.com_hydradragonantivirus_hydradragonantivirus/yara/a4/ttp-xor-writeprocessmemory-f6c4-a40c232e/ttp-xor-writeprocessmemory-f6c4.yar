rule TTP_XOR_WriteProcessMemory_f6c4 {
  strings:
    $key_f6c4 = { a1 b6 [2] 93 94 [2] 95 a1 [2] bb a1 [2] 84 bd }

  condition:
    any of them
}