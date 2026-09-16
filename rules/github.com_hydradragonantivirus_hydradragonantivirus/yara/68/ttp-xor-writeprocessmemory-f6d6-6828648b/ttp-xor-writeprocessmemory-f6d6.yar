rule TTP_XOR_WriteProcessMemory_f6d6 {
  strings:
    $key_f6d6 = { a1 a4 [2] 93 86 [2] 95 b3 [2] bb b3 [2] 84 af }

  condition:
    any of them
}