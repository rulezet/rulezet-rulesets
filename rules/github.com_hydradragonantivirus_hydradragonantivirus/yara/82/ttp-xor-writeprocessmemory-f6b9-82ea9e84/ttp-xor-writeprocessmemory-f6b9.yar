rule TTP_XOR_WriteProcessMemory_f6b9 {
  strings:
    $key_f6b9 = { a1 cb [2] 93 e9 [2] 95 dc [2] bb dc [2] 84 c0 }

  condition:
    any of them
}