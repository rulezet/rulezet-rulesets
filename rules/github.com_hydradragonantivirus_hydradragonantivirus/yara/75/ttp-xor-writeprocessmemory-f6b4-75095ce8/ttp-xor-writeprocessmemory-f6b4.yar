rule TTP_XOR_WriteProcessMemory_f6b4 {
  strings:
    $key_f6b4 = { a1 c6 [2] 93 e4 [2] 95 d1 [2] bb d1 [2] 84 cd }

  condition:
    any of them
}